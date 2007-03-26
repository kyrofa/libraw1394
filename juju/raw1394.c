/*						-*- c-basic-offset: 8 -*-
 *
 * raw1394.c -- Emulation of the raw1394 API on the juju stack
 *
 * Copyright (C) 2007  Kristian Hoegsberg <krh@bitplanet.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "juju.h"

raw1394_errcode_t
raw1394_get_errcode(raw1394handle_t handle)
{
	return handle->err;
}

int
raw1394_errcode_to_errno(raw1394_errcode_t errcode)
{
	switch (errcode) {

	case -RCODE_SEND_ERROR:
	case -RCODE_CANCELLED:
	case -RCODE_BUSY:
	case -RCODE_GENERATION:
	case -RCODE_NO_ACK:
		return EAGAIN;

	case raw1394_make_errcode(ACK_COMPLETE, RCODE_COMPLETE):
		return 0;
	case raw1394_make_errcode(ACK_COMPLETE, RCODE_CONFLICT_ERROR):
		return EAGAIN;
	case raw1394_make_errcode(ACK_COMPLETE, RCODE_DATA_ERROR):
		return EREMOTEIO;
	case raw1394_make_errcode(ACK_COMPLETE, RCODE_TYPE_ERROR):
		return EPERM;
	case raw1394_make_errcode(ACK_COMPLETE, RCODE_ADDRESS_ERROR):
		return EINVAL;
	default:
		return EINVAL;
	}
}

static int
juju_to_raw1394_errcode(int rcode)
{
	/* Best effort matching juju extended rcodes to raw1394 err
	 * code.  Since the raw1394 errcode decoding are macros we try
	 * to convert the juju rcodes to something that looks enough
	 * like the raw1394 errcodes that we retain ABI compatibility.
	 *
	 * Juju rcodes less than 0x10 are standard ieee1394 rcodes,
	 * which we map to a raw1394 errcode by or'ing in an
	 * ACK_COMPLETE ack code in the upper 16 bits.  Errors
	 * internal to raw1394 are negative values, but juju encodes
	 * these errors as rcodes greater than or equal to 0x10.  In
	 * this case, we just the negated value, which will look like
	 * an raw1394 internal error code. */

	if (rcode < 0x10)
		return raw1394_make_errcode(ACK_COMPLETE, rcode);
	else
		return -rcode;
}

static int
default_tag_handler(raw1394handle_t handle,
		    unsigned long tag, raw1394_errcode_t err)
{
	struct raw1394_reqhandle *rh = (struct raw1394_reqhandle *) tag;

	if (rh != NULL)
		return rh->callback(handle, rh->data, err);

	return -1;
}

static int
default_arm_tag_handler(raw1394handle_t handle, unsigned long arm_tag,
			byte_t type, unsigned int length, void *data)
{
	struct raw1394_arm_reqhandle *rh;

	if (arm_tag == 0)
		return -1;

	rh = (struct raw1394_arm_reqhandle *) arm_tag;

	return rh->arm_callback(handle, data, length, rh->pcontext, type);
}

static int
default_bus_reset_handler(struct raw1394_handle *handle, unsigned int gen)
{
	raw1394_update_generation(handle, gen);

	return 0;
}

static int
scan_devices(raw1394handle_t handle)
{
	DIR *dir;
	struct dirent *de;
	char filename[32];
	struct fw_cdev_get_info get_info;
	struct fw_cdev_event_bus_reset reset;
	int fd, err, i;
	struct port *ports;

	ports = handle->ports;
	memset(ports, 0, sizeof handle->ports);
	dir = opendir(FW_DEVICE_DIR);
	if (dir == NULL)
		return -1;

	i = 0;
	while (1) {
		de = readdir(dir);
		if (de == NULL)
			break;

		if (strncmp(de->d_name,
			    FW_DEVICE_PREFIX, strlen(FW_DEVICE_PREFIX)) != 0)
			continue;

		snprintf(filename, sizeof filename, FW_DEVICE_DIR "/%s", de->d_name);

		fd = open(filename, O_RDWR);
		if (fd < 0)
			continue;
		get_info.version = FW_CDEV_VERSION;
		get_info.rom = 0;
		get_info.rom_length = 0;
		get_info.bus_reset = ptr_to_u64(&reset);
		err = ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info);
		close(fd);

		if (err < 0)
			continue;

		if (i < MAX_PORTS && reset.node_id == reset.local_node_id) {
			strncpy(ports[i].device_file, filename,
				sizeof ports[i].device_file);
			ports[i].node_count = (reset.root_node_id & 0x3f) + 1;
			ports[i].card = get_info.card;
			i++;
		}
	}
	closedir(dir);

	handle->port_count = i;

	return 0;
}

static int
handle_echo_pipe(raw1394handle_t handle,
		 struct epoll_closure *ec, __uint32_t events)
{
	quadlet_t value;

	if (read(handle->pipe_fds[0], &value, sizeof value) < 0)
		return -1;

	return value;
}

static int
handle_lost_device(raw1394handle_t handle, int i)
{
	int phy_id;

	/* The device got unplugged, get rid of it.  The fd is
	 * automatically dropped from the epoll context when we close it. */

	close(handle->devices[i].fd);
	phy_id = handle->devices[i].node_id & 0x3f;
	if (handle->nodes[phy_id] == i)
		handle->nodes[phy_id] = -1;
	handle->devices[i].node_id = -1;

	return 0;
}

struct address_closure {
	int (*callback)(raw1394handle_t handle, struct address_closure *ac,
			struct fw_cdev_event_request *request, int i);
};

static int
handle_fcp_request(raw1394handle_t handle, struct address_closure *ac,
		   struct fw_cdev_event_request *request, int i)
{
	struct fw_cdev_send_response response;
	int is_response;

	response.serial = request->serial;
	response.rcode  = RCODE_COMPLETE;
	response.length = 0;
	response.data   = 0;

	if (handle->fcp_handler == NULL)
		response.rcode = RCODE_ADDRESS_ERROR;

	if (request->tcode >= TCODE_WRITE_RESPONSE)
		response.rcode = RCODE_CONFLICT_ERROR;

	if (ioctl(handle->devices[i].fd,
		  FW_CDEV_IOC_SEND_RESPONSE, &response) < 0)
		return -1;

	if (response.rcode != RCODE_COMPLETE)
		return 0;

	is_response = request->offset >= CSR_REGISTER_BASE + CSR_FCP_RESPONSE;

	return handle->fcp_handler(handle,
				   handle->devices[i].node_id,
				   is_response,
				   request->length,
				   (unsigned char *) request->data);
}

static int
handle_device_event(raw1394handle_t handle,
		    struct epoll_closure *ec, __uint32_t events)
{
	union fw_cdev_event *u;
	struct device *device = (struct device *) ec;
	struct address_closure *ac;
	struct request_closure *rc;
	raw1394_errcode_t errcode;
	int len, phy_id;
	int i;

	i = device - handle->devices;
	if (events == EPOLLHUP)
		return handle_lost_device(handle, i);

	len = read(handle->devices[i].fd,
		   handle->buffer, sizeof handle->buffer);
	if (len < 0)
		return -1;

	u = (void *) handle->buffer;
	switch (u->common.type) {
	case FW_CDEV_EVENT_BUS_RESET:
		/* Clear old entry, unless it's been overwritten. */
		phy_id = handle->devices[i].node_id & 0x3f;
		if (handle->nodes[phy_id] == i)
			handle->nodes[phy_id] = -1;
		handle->nodes[u->bus_reset.node_id & 0x3f] = i;
		handle->devices[i].node_id = u->bus_reset.node_id;
		handle->devices[i].generation = u->bus_reset.generation;

		if (u->bus_reset.node_id != u->bus_reset.local_node_id)
			return 0;

		memcpy(&handle->reset, &u->bus_reset, sizeof handle->reset);
		return handle->bus_reset_handler(handle,
						 u->bus_reset.generation);

	case FW_CDEV_EVENT_RESPONSE:
		rc = u64_to_ptr(u->response.closure);

		if (rc->data != NULL)
			memcpy(rc->data, u->response.data, rc->length);

		errcode = juju_to_raw1394_errcode(u->response.rcode);

		return handle->tag_handler(handle, rc->tag, errcode);

	case FW_CDEV_EVENT_REQUEST:
		ac = u64_to_ptr(u->request.closure);
		return ac->callback(handle, ac, &u->request, i);

	default:
	case FW_CDEV_EVENT_ISO_INTERRUPT:
		/* Never happens. */
		return -1;
	}
}

static int
handle_inotify(raw1394handle_t handle, struct epoll_closure *ec,
	       __uint32_t events)
{
	struct inotify_event *event;
	char filename[32];
	struct fw_cdev_get_info info;
	struct fw_cdev_event_bus_reset reset;
	struct epoll_event ep;
	int i, len, fd, phy_id;

	event = (struct inotify_event *) handle->buffer;
	len = read(handle->inotify_fd, event, BUFFER_SIZE);
	if (!(event->mask & IN_CREATE))
		return -1;
	if (strncmp(event->name,
		    FW_DEVICE_PREFIX, strlen(FW_DEVICE_PREFIX)) != 0)
		return 0;
	snprintf(filename, sizeof filename, FW_DEVICE_DIR "/%s", event->name);
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		switch (errno) {
		case ENOENT:
			/* Huh, it disappeared before we could
			 * open it. */
			return 0;
		case EACCES:
			/* We don't have permission to talk to
			 * this device, maybe it's a storage
			 * device. */
			return 0;
		default:
			/* Anything else is bad news. */
			return -1;
		}
	}

	info.version = FW_CDEV_VERSION;
	info.rom = 0;
	info.rom_length = 0;
	info.bus_reset = ptr_to_u64(&reset);
	if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &info) < 0) {
		close(fd);
		return -1;
	}

	for (i = 0; i < MAX_DEVICES; i++)
		if (handle->devices[i].node_id == -1)
			break;
	if (i == MAX_DEVICES) {
		close(fd);
		return -1;
	}

	phy_id = reset.node_id & 0x3f;
	handle->nodes[phy_id] = i;
	handle->devices[i].node_id = reset.node_id;
	handle->devices[i].generation = reset.generation;
	handle->devices[i].fd = fd;
	strncpy(handle->devices[i].filename, filename,
		sizeof handle->devices[i].filename);
	handle->devices[i].closure.func = handle_device_event;
	ep.events = EPOLLIN;
	ep.data.ptr = &handle->devices[i].closure;
	if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD, fd, &ep) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

int raw1394_loop_iterate(raw1394handle_t handle)
{
	int i, count, retval = 0;
	struct epoll_closure *closure;
	struct epoll_event ep[32];

	count = epoll_wait(handle->epoll_fd, ep, ARRAY_LENGTH(ep), -1);
	if (count < 0)
		return -1;

	for (i = 0; i < count; i++) {
		closure = ep[i].data.ptr;
		retval = closure->func(handle, closure, ep[i].events);
	}

	/* It looks like we have to add this work-around to get epoll
	 * to recompute the POLLIN status of the epoll_fd. */
	epoll_wait(handle->epoll_fd, ep, ARRAY_LENGTH(ep), 0);

	return retval;
}

raw1394handle_t raw1394_new_handle(void)
{
	raw1394handle_t handle;
	struct epoll_event ep;
	int i;

	handle = malloc(sizeof *handle);

	handle->tag_handler = default_tag_handler;
	handle->arm_tag_handler = default_arm_tag_handler;
	handle->allocations = NULL;

	handle->notify_bus_reset = RAW1394_NOTIFY_ON;
	handle->bus_reset_handler = default_bus_reset_handler;

	handle->iso.fd = -1;

	handle->epoll_fd = epoll_create(16);
	if (handle->epoll_fd < 0)
		goto out_handle;

	if (pipe(handle->pipe_fds) < 0)
		goto out_epoll;

	handle->inotify_fd = inotify_init();
	if (handle->inotify_fd < 0)
		goto out_pipe;

	handle->inotify_watch =
		inotify_add_watch(handle->inotify_fd, FW_DEVICE_DIR, IN_CREATE);
	if (handle->inotify_watch < 0)
		goto out_inotify;

	handle->pipe_closure.func = handle_echo_pipe;
	ep.events = EPOLLIN;
	ep.data.ptr = &handle->pipe_closure;
	if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD,
		      handle->pipe_fds[0], &ep) < 0)
		goto out_inotify;

	handle->inotify_closure.func = handle_inotify;
	ep.events = EPOLLIN;
	ep.data.ptr = &handle->inotify_closure;
	if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD,
		      handle->inotify_fd, &ep) < 0)
		goto out_inotify;

	for (i = 0; i < MAX_DEVICES; i++) {
		handle->nodes[i] = -1;
		handle->devices[i].node_id = -1;
	}

	scan_devices(handle);

	return handle;

 out_inotify:
	close(handle->inotify_fd);
 out_pipe:
	close(handle->pipe_fds[0]);
	close(handle->pipe_fds[1]);
 out_epoll:
	close(handle->epoll_fd);
 out_handle:
	free(handle);
	return NULL;
}

void raw1394_destroy_handle(raw1394handle_t handle)
{
	int i;

	close(handle->inotify_fd);
	close(handle->pipe_fds[0]);
	close(handle->pipe_fds[1]);

	for (i = 0; i < MAX_DEVICES; i++) {
		if (handle->devices[i].node_id == -1)
			continue;

		close(handle->devices[i].fd);
	}

	close(handle->epoll_fd);

	free(handle);

	return;
}

raw1394handle_t raw1394_new_handle_on_port(int port)
{
	raw1394handle_t handle;

	handle = raw1394_new_handle();
	if (handle == NULL)
		return NULL;

	if (raw1394_set_port(handle, port) < 0)
		return NULL;

	return handle;
}

int raw1394_busreset_notify (raw1394handle_t handle, int off_on_switch)
{
	handle->notify_bus_reset = off_on_switch;

	return 0;
}

int raw1394_get_fd(raw1394handle_t handle)
{
	return handle->epoll_fd;
}

void raw1394_set_userdata(raw1394handle_t handle, void *data)
{
	handle->user_data = data;
}

void *raw1394_get_userdata(raw1394handle_t handle)
{
	return handle->user_data;
}

nodeid_t raw1394_get_local_id(raw1394handle_t handle)
{
	return handle->reset.local_node_id;
}

nodeid_t raw1394_get_irm_id(raw1394handle_t handle)
{
	return handle->reset.irm_node_id;
}

int raw1394_get_nodecount(raw1394handle_t handle)
{
	return (handle->reset.root_node_id & 0x3f) + 1;
}

int raw1394_get_port_info(raw1394handle_t handle,
			  struct raw1394_portinfo *pinf,
			  int maxports)
{
	int i;

	if (maxports >= handle->port_count)
		maxports = handle->port_count;

	for (i = 0; i < maxports; i++) {
		pinf[i].nodes = handle->ports[i].node_count;
		strncpy(pinf[i].name, handle->ports[i].device_file,
			sizeof pinf[i].name);
	}

	return handle->port_count;
}

int raw1394_set_port(raw1394handle_t handle, int port)
{
	struct fw_cdev_get_info get_info;
	struct fw_cdev_event_bus_reset reset;
	struct epoll_event ep;
	struct dirent *de;
	char filename[32];
	DIR *dir;
	int i, fd, phy_id;

	if (port >= handle->port_count) {
		errno = EINVAL;
		return -1;
	}

	dir = opendir("/dev");
	if (dir == NULL)
		return -1;

	for (i = 0; i < MAX_DEVICES; ) {
		de = readdir(dir);
		if (de == NULL)
			break;

		if (strncmp(de->d_name, "fw", 2) != 0)
			continue;

		snprintf(filename, sizeof filename, "/dev/%s", de->d_name);

		fd = open(filename, O_RDWR);
		if (fd < 0)
			continue;

		get_info.version = FW_CDEV_VERSION;
		get_info.rom = 0;
		get_info.rom_length = 0;
		get_info.bus_reset = ptr_to_u64(&reset);
		if (ioctl(fd, FW_CDEV_IOC_GET_INFO, &get_info) < 0) {
			close(fd);
			continue;
		}

		if (get_info.card != handle->ports[port].card) {
			close(fd);
			continue;
		}

		phy_id = reset.node_id & 0x3f;
		handle->nodes[phy_id] = i;
		handle->devices[i].node_id = reset.node_id;
		handle->devices[i].generation = reset.generation;
		handle->devices[i].fd = fd;
		strncpy(handle->devices[i].filename, filename,
			sizeof handle->devices[i].filename);

		handle->devices[i].closure.func = handle_device_event;
		ep.events = EPOLLIN;
		ep.data.ptr = &handle->devices[i].closure;
		if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD, fd, &ep) < 0) {
			close(fd);
			return -1;
		}

		handle->generation = reset.generation;
		if (reset.node_id == reset.local_node_id) {
			memcpy(&handle->reset, &reset, sizeof handle->reset);
			handle->local_fd = fd;
			strncpy(handle->local_filename, filename,
				sizeof handle->local_filename);
		}

		i++;
	}

	return 0;
}

int raw1394_reset_bus(raw1394handle_t handle)
{
	return raw1394_reset_bus_new(handle, RAW1394_LONG_RESET);
}

int raw1394_reset_bus_new(raw1394handle_t handle, int type)
{
	struct fw_cdev_initiate_bus_reset initiate;

	switch (type) {
	case RAW1394_LONG_RESET:
		initiate.type = FW_CDEV_LONG_RESET;
		break;
	case RAW1394_SHORT_RESET:
		initiate.type = FW_CDEV_SHORT_RESET;
		break;
	}

	return ioctl(handle->local_fd,
		     FW_CDEV_IOC_INITIATE_BUS_RESET, &initiate);
}

bus_reset_handler_t raw1394_set_bus_reset_handler(raw1394handle_t handle,
						  bus_reset_handler_t new_h)
{
	bus_reset_handler_t old_h = handle->bus_reset_handler;

	handle->bus_reset_handler = new_h;

	return old_h;
}

unsigned int raw1394_get_generation(raw1394handle_t handle)
{
	return handle->generation;
}

void raw1394_update_generation(raw1394handle_t handle, unsigned int generation)
{
	handle->generation = generation;
}

tag_handler_t
raw1394_set_tag_handler(raw1394handle_t handle, tag_handler_t new_h)
{
	tag_handler_t old_h = handle->tag_handler;

	handle->tag_handler = new_h;

	return old_h;
}

arm_tag_handler_t
raw1394_set_arm_tag_handler(raw1394handle_t handle, arm_tag_handler_t new_h)
{
	arm_tag_handler_t old_h = handle->arm_tag_handler;

	handle->arm_tag_handler = new_h;

	return old_h;
}

fcp_handler_t
raw1394_set_fcp_handler(raw1394handle_t handle, fcp_handler_t new_h)
{
	fcp_handler_t old_h = handle->fcp_handler;

	handle->fcp_handler = new_h;

	return old_h;
}

struct request_response_block {
	struct raw1394_arm_request_response request_response;
	struct raw1394_arm_request request;
	struct raw1394_arm_response response;
	unsigned char data[0];
};

struct allocation {
	struct address_closure closure;
	struct allocation *next;
	byte_t *buffer;
	octlet_t tag;
	arm_options_t access_rights;
	arm_options_t notification_options;
	arm_options_t client_transactions;
	nodeaddr_t offset;
	size_t length;
	unsigned char data[0];
};

static int
handle_arm_request(raw1394handle_t handle, struct address_closure *ac,
		   struct fw_cdev_event_request *request, int i)
{
	struct allocation *allocation = (struct allocation *) ac;
	struct request_response_block *rrb;
	struct fw_cdev_send_response response;
	arm_options_t type;
	size_t in_length;
	int offset;

	offset = request->offset - allocation->offset;
	response.serial = request->serial;

	switch (request->tcode) {
	case TCODE_WRITE_QUADLET_REQUEST:
	case TCODE_WRITE_BLOCK_REQUEST:
		printf("got write request, offset=0x%012llx, length=%d\n",
		       request->offset, request->length);

		type = RAW1394_ARM_WRITE;
		in_length = request->length;
		response.rcode  = RCODE_COMPLETE;
		response.length = 0;
		response.data   = 0;
		break;

	case TCODE_READ_QUADLET_REQUEST:
	case TCODE_READ_BLOCK_REQUEST:
		printf("got read request, offset=0x%012llx, length=%d\n",
		       request->offset, request->length);

		type = RAW1394_ARM_READ;
		in_length = 0;
		response.rcode = RCODE_COMPLETE;
		response.length = request->length;
		response.data = ptr_to_u64(allocation->data + offset);
		break;

	case TCODE_LOCK_REQUEST:
		type = RAW1394_ARM_LOCK;
		in_length = request->length;
		response.length = 4;
		break;

	default:
		in_length = 0;
		type = 0;
		break;
	}

	if (!(allocation->access_rights & type)) {
		response.rcode  = RCODE_TYPE_ERROR;
		response.length = 0;
		response.data   = 0;
		if (ioctl(handle->devices[i].fd,
			  FW_CDEV_IOC_SEND_RESPONSE, &response) < 0)
			return -1;
	} else if (!(allocation->client_transactions & type)) {
		if (type == RAW1394_ARM_WRITE)
			memcpy(allocation->data + offset,
			       request->data, request->length);
		else if (type == RAW1394_ARM_LOCK)
			/* FIXME: do lock ops here */;

		if (ioctl(handle->devices[i].fd,
			  FW_CDEV_IOC_SEND_RESPONSE, &response) < 0)
			return -1;
	}

	if (!(allocation->notification_options & type))
		return 0;

	rrb = malloc(sizeof *rrb + in_length + response.length);

	rrb->request_response.request = &rrb->request;
	rrb->request_response.response = &rrb->response;

	rrb->request.destination_nodeid = handle->reset.local_node_id;
	rrb->request.source_nodeid = handle->devices[i].node_id;
	rrb->request.destination_offset = request->offset;
	rrb->request.tlabel = 0;
	if (request->tcode < 0x10) {
		rrb->request.tcode = request->tcode;
		rrb->request.extended_transaction_code = 0;
	} else {
		rrb->request.tcode = TCODE_LOCK_REQUEST;
		rrb->request.extended_transaction_code = request->tcode - 0x10;
	}
	rrb->request.generation = handle->reset.generation;
	rrb->request.buffer_length = in_length;
	memcpy(rrb->request.buffer, request->data, in_length);

	rrb->response.response_code = response.rcode;
	rrb->response.buffer_length = response.length;
	memcpy(rrb->response.buffer,
	       allocation->data + offset, response.length);

	return handle->arm_tag_handler(handle, allocation->tag, type,
				       request->length,
				       &rrb->request_response);
}

int
raw1394_arm_register(raw1394handle_t handle, nodeaddr_t start,
		     size_t length, byte_t *initial_value,
		     octlet_t arm_tag, arm_options_t access_rights,
		     arm_options_t notification_options,
		     arm_options_t client_transactions)
{
	struct fw_cdev_allocate request;
	struct allocation *allocation;
	int retval;

	allocation = malloc(sizeof *allocation + length);
	if (allocation == NULL)
		return -1;

	allocation->closure.callback = handle_arm_request;
	allocation->buffer = initial_value;
	allocation->tag = arm_tag;
	allocation->access_rights = access_rights;
	allocation->notification_options = notification_options;
	allocation->client_transactions = client_transactions;
	allocation->offset = start;
	allocation->length = length;
	if (initial_value != NULL)
		memcpy(allocation->data, initial_value, length);

	request.offset = start;
	request.length = length;
	request.closure = ptr_to_u64(&allocation->closure);

	retval = ioctl(handle->local_fd, FW_CDEV_IOC_ALLOCATE, &request);
	if (retval < 0) {
		free(allocation);
		return -1;
	}

	allocation->next = handle->allocations;
	handle->allocations = allocation;

	return 0;
}

static struct allocation *
lookup_allocation(raw1394handle_t handle, nodeaddr_t start, int delete)
{
	struct allocation *a, **prev;

	prev = &handle->allocations;
	for (a = handle->allocations; a != NULL; a = a->next) {
		if (a->offset <= start && start < a->offset + a->length)
			break;
		prev = &a->next;
	}

	if (a != NULL && delete)
		*prev = a->next;

	return a;
}

int
raw1394_arm_unregister(raw1394handle_t handle, nodeaddr_t start)
{
	struct fw_cdev_deallocate request;
	struct allocation *allocation;

	allocation = lookup_allocation(handle, start, 1);
	if (allocation == NULL) {
		errno = EINVAL;
		return -1;
	}

	free(allocation);

	request.offset = start;

	return ioctl(handle->local_fd, FW_CDEV_IOC_DEALLOCATE, &request);
}

int
raw1394_arm_set_buf(raw1394handle_t handle, nodeaddr_t start,
		    size_t length, void *buf)
{
	struct allocation *allocation;

	allocation = lookup_allocation(handle, start, 0);
	if (allocation == NULL) {
		errno = ENOENT;
		return -1;
	}

	memcpy(allocation->data + allocation->offset - start, buf, length);

	return 0;
}

int
raw1394_arm_get_buf(raw1394handle_t handle, nodeaddr_t start,
		    size_t length, void *buf)
{
	struct allocation *allocation;

	allocation = lookup_allocation(handle, start, 0);
	if (allocation == NULL) {
		errno = ENOENT;
		return -1;
	}

	memcpy(buf, allocation->data + allocation->offset - start, length);

	return 0;
}

int
raw1394_echo_request(raw1394handle_t handle, quadlet_t data)
{
	return write(handle->pipe_fds[1], &data, sizeof data);
}

int raw1394_wake_up(raw1394handle_t handle)
{
	return raw1394_echo_request(handle, 0);
}

int raw1394_phy_packet_write (raw1394handle_t handle, quadlet_t data)
{
	errno = ENOSYS;
	return -1;
}

int
raw1394_start_phy_packet_write(raw1394handle_t handle,
			       quadlet_t data, unsigned long tag)
{
	errno = ENOSYS;
	return -1;
}

static int
send_request(raw1394handle_t handle, int tcode,
	     nodeid_t node, nodeaddr_t addr,
	     size_t length, void *in, void *out, unsigned long tag)
{
	struct fw_cdev_send_request *request;
	struct request_closure *closure;
	int i;

	if (node > handle->reset.root_node_id) {
		handle->err = -RCODE_NO_ACK;
		errno = raw1394_errcode_to_errno(handle->err);
		return -1;
	}

	i = handle->nodes[node & 0x3f];
	if (i == -1) {
		handle->err = -RCODE_NO_ACK;
		errno = raw1394_errcode_to_errno(handle->err);
		return -1;
	}

	if (handle->generation != handle->devices[i].generation) {
		handle->err = -RCODE_GENERATION;
		errno = raw1394_errcode_to_errno(handle->err);
		return -1;
	}

	closure = malloc(sizeof *closure);
	if (closure == NULL) {
		handle->err = -RCODE_SEND_ERROR;
		errno = raw1394_errcode_to_errno(handle->err);
		return -1;
	}

	closure->data = out;
	closure->length = length;
	closure->tag = tag;

	request = (struct fw_cdev_send_request *) handle->buffer;
	request->tcode = tcode;
	request->generation = handle->generation;
	request->offset = addr;
	request->length = length;
	request->closure = ptr_to_u64(closure);
	request->data = ptr_to_u64(in);

	return ioctl(handle->devices[i].fd, FW_CDEV_IOC_SEND_REQUEST, request);
}

int
raw1394_start_read(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
		   size_t length, quadlet_t *buffer, unsigned long tag)
{
	int tcode;

	if (length == 4)
		tcode = TCODE_READ_QUADLET_REQUEST;
	else
		tcode = TCODE_READ_BLOCK_REQUEST;

	return send_request(handle, tcode,
			    node, addr, length, NULL, buffer, tag);
}

int
raw1394_start_write(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
		    size_t length, quadlet_t *data, unsigned long tag)
{
	int tcode;

	if (length == 4)
		tcode = TCODE_WRITE_QUADLET_REQUEST;
	else
		tcode = TCODE_WRITE_BLOCK_REQUEST;

	return send_request(handle, tcode,
			    node, addr, length, data, NULL, tag);
}

static int
setup_lock(int extcode, quadlet_t data, quadlet_t arg, quadlet_t *buffer)
{
	switch (extcode) {
	case RAW1394_EXTCODE_FETCH_ADD:
	case RAW1394_EXTCODE_LITTLE_ADD:
		buffer[0] = data;
		return sizeof buffer[0];

	case RAW1394_EXTCODE_MASK_SWAP:
	case RAW1394_EXTCODE_COMPARE_SWAP:
	case RAW1394_EXTCODE_BOUNDED_ADD:
	case RAW1394_EXTCODE_WRAP_ADD:
		buffer[0] = arg;
		buffer[1] = data;
		return sizeof buffer;

	default:
		errno = EINVAL;
		return -1;
	}
}

static int
setup_lock64(int extcode, octlet_t data, octlet_t arg, octlet_t *buffer)
{
	switch (extcode) {
	case RAW1394_EXTCODE_FETCH_ADD:
	case RAW1394_EXTCODE_LITTLE_ADD:
		buffer[0] = data;
		return sizeof buffer[0];

	case RAW1394_EXTCODE_MASK_SWAP:
	case RAW1394_EXTCODE_COMPARE_SWAP:
	case RAW1394_EXTCODE_BOUNDED_ADD:
	case RAW1394_EXTCODE_WRAP_ADD:
		buffer[0] = arg;
		buffer[1] = data;
		return sizeof buffer;

	default:
		errno = EINVAL;
		return -1;
	}
}

int
raw1394_start_lock(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
		   unsigned int extcode, quadlet_t data, quadlet_t arg,
		   quadlet_t *result, unsigned long tag)
{
	quadlet_t buffer[2];
	int length;

	length = setup_lock(extcode, data, arg, buffer);
	if (length < 0)
		return length;

	return send_request(handle, 16 + extcode,
			    node, addr, length, buffer, result, tag);
}

int
raw1394_start_lock64(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
		     unsigned int extcode, octlet_t data, octlet_t arg,
		     octlet_t *result, unsigned long tag)
{
	octlet_t buffer[2];
	int length;

	length = setup_lock64(extcode, data, arg, buffer);
	if (length < 0)
		return length;

	return send_request(handle, 16 + extcode,
			    node, addr, length, buffer, result, tag);
}

int
raw1394_start_async_stream(raw1394handle_t handle, unsigned int channel,
			   unsigned int tag, unsigned int sy,
			   unsigned int speed, size_t length, quadlet_t *data,
			   unsigned long rawtag)
{
	/* FIXME: implement this? */
	return -1;
}


int
raw1394_start_async_send(raw1394handle_t handle,
			 size_t length, size_t header_length,
			 unsigned int expect_response,
			 quadlet_t *data, unsigned long rawtag)
{
	/* FIXME: implement this? */
	return -1;
}

struct sync_data {
	raw1394_errcode_t err;
	int done;
};

static int
sync_callback(raw1394handle_t handle, void *data, raw1394_errcode_t err)
{
	struct sync_data *sd = data;

	sd->err = err;
	sd->done = 1;

	return 0;
}

static int
send_request_sync(raw1394handle_t handle, int tcode,
		  nodeid_t node, nodeaddr_t addr,
		  size_t length, void *in, void *out)
{
	struct raw1394_reqhandle reqhandle;
	struct sync_data sd = { 0, 0 };
	int err;

	reqhandle.callback = sync_callback;
	reqhandle.data = &sd;

	err = send_request(handle, tcode, node, addr,
			   length, in, out, (unsigned long) &reqhandle);

	while (!sd.done) {
		if (err < 0)
			return err;
		err = raw1394_loop_iterate(handle);
	}

	handle->err = sd.err;
	errno = raw1394_errcode_to_errno(sd.err);

	return (errno ? -1 : 0);
}

int
raw1394_read(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
	     size_t length, quadlet_t *buffer)
{
	int tcode;

	if (length == 4)
		tcode = TCODE_READ_QUADLET_REQUEST;
	else
		tcode = TCODE_READ_BLOCK_REQUEST;

	return send_request_sync(handle, tcode,
				 node, addr, length, NULL, buffer);
}

int
raw1394_write(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
	      size_t length, quadlet_t *data)
{
	int tcode;

	if (length == 4)
		tcode = TCODE_WRITE_QUADLET_REQUEST;
	else
		tcode = TCODE_WRITE_BLOCK_REQUEST;

	return send_request_sync(handle, tcode,
				 node, addr, length, data, NULL);
}

int
raw1394_lock(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
	     unsigned int extcode, quadlet_t data, quadlet_t arg,
	     quadlet_t *result)
{
	quadlet_t buffer[2];
	size_t length;

	length = setup_lock(extcode, data, arg, buffer);
	if (length < 0)
		return length;

	return send_request_sync(handle, 16 + extcode, node, addr,
				 length, buffer, result);
}

int
raw1394_lock64(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
	       unsigned int extcode, octlet_t data, octlet_t arg,
	       octlet_t *result)
{
	octlet_t buffer[2];
	size_t length;

	length = setup_lock64(extcode, data, arg, buffer);
	if (length < 0)
		return length;

	return send_request_sync(handle, 16 + extcode, node, addr,
				 length, buffer, result);
}

int
raw1394_async_stream(raw1394handle_t handle, unsigned int channel,
		     unsigned int tag, unsigned int sy, unsigned int speed,
		     size_t length, quadlet_t *data)
{
	/* FIXME: implement this? */
	return -1;
}

int
raw1394_async_send(raw1394handle_t handle,
		   size_t length, size_t header_length,
		   unsigned int expect_response,
		   quadlet_t *data)
{
	/* FIXME: implement this? */
	return -1;
}

int
raw1394_start_fcp_listen(raw1394handle_t handle)
{
	struct fw_cdev_allocate request;
	struct address_closure *closure;

	closure = malloc(sizeof *closure);
	if (closure == NULL)
		return -1;

	closure->callback = handle_fcp_request;

	request.offset = CSR_REGISTER_BASE + CSR_FCP_COMMAND;
	request.length = CSR_FCP_END - CSR_FCP_COMMAND;
	request.closure = ptr_to_u64(closure);
	if (ioctl(handle->local_fd, FW_CDEV_IOC_ALLOCATE, &request) < 0)
		return -1;

	return 0;
}

int
raw1394_stop_fcp_listen(raw1394handle_t handle)
{
	struct fw_cdev_deallocate request;

	request.offset = CSR_REGISTER_BASE + CSR_FCP_COMMAND;

	return ioctl(handle->local_fd, FW_CDEV_IOC_DEALLOCATE, &request);
}

const char *
raw1394_get_libversion(void)
{
	return VERSION " (Juju)";
}

int
raw1394_update_config_rom(raw1394handle_t handle, const quadlet_t *new_rom,
			  size_t size, unsigned char rom_version)
{
	return -1;
}

int
raw1394_get_config_rom(raw1394handle_t handle, quadlet_t *buffer,
		       size_t buffersize, size_t *rom_size,
		       unsigned char *rom_version)
{
	struct fw_cdev_get_info get_info;
	int err;

	get_info.version = FW_CDEV_VERSION;
	get_info.rom = ptr_to_u64(buffer);
	get_info.rom_length = buffersize;
	get_info.bus_reset = 0;

	err = ioctl(handle->local_fd, FW_CDEV_IOC_GET_INFO, &get_info);
	if (err)
		return err;

	*rom_size = get_info.rom_length;
	*rom_version = 0;

	return 0;
}

#define MAXIMUM_BANDWIDTH 4915

int
raw1394_bandwidth_modify (raw1394handle_t handle,
			  unsigned int bandwidth,
			  enum raw1394_modify_mode mode)
{
        quadlet_t buffer, compare, swap;
	nodeaddr_t addr;
        int result;

        if (bandwidth == 0)
                return 0;
        
	addr = CSR_REGISTER_BASE + CSR_BANDWIDTH_AVAILABLE;
        /* Read current bandwidth usage from IRM. */
        result = raw1394_read (handle, raw1394_get_irm_id (handle), addr,
			       sizeof buffer, &buffer);
        if (result < 0)
                return -1;

        compare = ntohl (buffer);
	switch (mode) {
	case RAW1394_MODIFY_ALLOC:
		swap = compare - bandwidth;
		if (swap < 0)
			return -1;
		break;

	case RAW1394_MODIFY_FREE:
		swap = compare + bandwidth;
		if (swap > MAXIMUM_BANDWIDTH)
			swap = MAXIMUM_BANDWIDTH;
		break;

	default:
		return -1;
	}

	result = raw1394_lock(handle, raw1394_get_irm_id (handle), addr,
			      RAW1394_EXTCODE_COMPARE_SWAP,
			      htonl(swap), htonl(compare), &buffer);
	if (result < 0 || ntohl(buffer) != compare)
		return -1;
  
        return 0;
}

int
raw1394_channel_modify (raw1394handle_t handle,
			unsigned int channel,
			enum raw1394_modify_mode mode)
{
        quadlet_t buffer, compare, swap, bit;
        nodeaddr_t addr;
        int result;
        
	if (channel >= 64)
		return -1;
	addr = CSR_REGISTER_BASE +
		CSR_CHANNELS_AVAILABLE_HI + 4 * (channel / 32);
	/* Read currently available channels from IRM. */
        result = raw1394_read(handle, raw1394_get_irm_id (handle), addr, 
			      sizeof buffer, &buffer);
        if (result < 0)
                return -1;
        
	/* IEEE numbers bits from MSB (0) to LSB (31). */
        bit = 1 << (31 - (channel & 31));
        compare = ntohl(buffer);
	switch (mode) {
	case RAW1394_MODIFY_ALLOC:
                if ((compare & bit) == 0)
                        return -1;
                swap = buffer & ~bit;
		break;

        case RAW1394_MODIFY_FREE:
                if ((buffer & bit) != 0)
                        return -1;
                swap = buffer | bit;
		break;

	default:
		return -1;
        }
  
        result = raw1394_lock (handle, raw1394_get_irm_id (handle), addr,
			       RAW1394_EXTCODE_COMPARE_SWAP,
			       htonl(swap), htonl(compare), &buffer);

        if (result < 0 || ntohl(buffer) != compare)
                return -1;
  
        return 0;
}
