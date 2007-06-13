/*						-*- c-basic-offset: 8 -*-
 *
 * raw1394-iso.c -- Emulation of the raw1394 rawiso API on the juju stack
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

#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

#include "juju.h"

static int
queue_packet(raw1394handle_t handle,
	     unsigned int length, unsigned int header_length,
	     unsigned char tag, unsigned char sy)
{
	struct fw_cdev_queue_iso queue_iso;
	struct fw_cdev_iso_packet *p;
	int err;

	p = &handle->iso.packets[handle->iso.packet_index];
	p->control =
		FW_CDEV_ISO_PAYLOAD_LENGTH(length) |
		FW_CDEV_ISO_TAG(tag) |
		FW_CDEV_ISO_SY(sy) |
		FW_CDEV_ISO_HEADER_LENGTH(header_length);

	if (handle->iso.packet_phase == handle->iso.irq_interval - 1)
		p->control |= FW_CDEV_ISO_INTERRUPT;

	handle->iso.head += length;
	handle->iso.packet_count++;
	handle->iso.packet_phase++;
	handle->iso.packet_index++;

	if (handle->iso.packet_phase == handle->iso.irq_interval)
		handle->iso.packet_phase = 0;

	if (handle->iso.head + handle->iso.max_packet_size > handle->iso.buffer_end)
		handle->iso.head = handle->iso.buffer;

	/* Queue the packets in the kernel if we filled up the packets
	 * array or wrapped the payload buffer. */
	if (handle->iso.packet_index == handle->iso.irq_interval ||
	    handle->iso.head == handle->iso.buffer) {
		queue_iso.packets = ptr_to_u64(handle->iso.packets);
		queue_iso.size    = handle->iso.packet_index * sizeof handle->iso.packets[0];
		queue_iso.data    = ptr_to_u64(handle->iso.first_payload);
		queue_iso.handle  = 0;
		handle->iso.packet_index = 0;
		handle->iso.first_payload = handle->iso.head;

		err = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
		if (err < 0)
			return -1;
	}
}

static int
queue_xmit_packets(raw1394handle_t handle, int limit)
{
	enum raw1394_iso_disposition d;
	unsigned char tag, sy;
	int len, cycle, dropped;

	if (handle->iso.xmit_handler == NULL)
		return 0;

	while (handle->iso.packet_count < limit) {

		d = handle->iso.xmit_handler(handle, handle->iso.head,
					     &len, &tag, &sy, cycle, dropped);

		switch (d) {
		case RAW1394_ISO_OK:
			queue_packet(handle, len, 0, tag, sy);
			break;
		case RAW1394_ISO_DEFER:
		case RAW1394_ISO_AGAIN:
		default:
			return 0;
		case RAW1394_ISO_ERROR:
			return -1;
		case RAW1394_ISO_STOP:
			raw1394_iso_stop(handle);
			return 0;
		}
	}

	return 0;
}

int raw1394_iso_xmit_start(raw1394handle_t handle, int start_on_cycle,
			   int prebuffer_packets)
{
	struct fw_cdev_start_iso start_iso;
	int retval;

	if (prebuffer_packets == -1)
		prebuffer_packets = handle->iso.irq_interval;

	handle->iso.prebuffer = prebuffer_packets;
	handle->iso.start_on_cycle = start_on_cycle;

	queue_xmit_packets(handle, prebuffer_packets);

	if (handle->iso.prebuffer <= handle->iso.packet_count) {
		start_iso.cycle  = start_on_cycle;
		start_iso.handle = 0;

		retval = ioctl(handle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (retval < 0)
			return retval;
	}

	return queue_xmit_packets(handle, handle->iso.buf_packets);
}

static int
queue_recv_packets(raw1394handle_t handle)
{
	while (handle->iso.packet_count <= handle->iso.buf_packets)
		queue_packet(handle, handle->iso.max_packet_size, 4, 0, 0);

	return 0;
}
 
static enum raw1394_iso_disposition
flush_recv_packets(raw1394handle_t handle,
		   struct fw_cdev_event_iso_interrupt *interrupt)
{
	enum raw1394_iso_disposition d;
	quadlet_t header, *p, *end;
	unsigned int len, cycle, dropped;
	unsigned char channel, tag, sy;

	p = interrupt->header;
	end = (void *) interrupt->header + interrupt->header_length;
	cycle = interrupt->cycle;
	dropped = 0;
	d = RAW1394_ISO_OK;

	while (p < end) {
		header = be32_to_cpu(*p++);
		len = header >> 16;
		tag = (header >> 14) & 0x3;
		channel = (header >> 8) & 0x3f;
		sy = header & 0x0f;

		d = handle->iso.recv_handler(handle, handle->iso.tail, len,
					     channel, tag, sy, cycle, dropped);
		if (d != RAW1394_ISO_OK)
			/* FIXME: we need to save the headers so we
			 * can restart this loop. */
			break;
		cycle++;

		handle->iso.tail += handle->iso.max_packet_size;
		handle->iso.packet_count--;

		if (handle->iso.tail + handle->iso.max_packet_size > handle->iso.buffer_end)
			handle->iso.tail = handle->iso.buffer;
	}

	switch (d) {
	case RAW1394_ISO_OK:
	case RAW1394_ISO_DEFER:
	default:
		break;
		
	case RAW1394_ISO_ERROR:
		return -1;

	case RAW1394_ISO_STOP:
		raw1394_iso_stop(handle);
		return 0;		
	}

	queue_recv_packets(handle);

	return 0;
}

int raw1394_iso_recv_start(raw1394handle_t handle, int start_on_cycle,
			   int tag_mask, int sync)
{
	struct fw_cdev_start_iso start_iso;

	queue_recv_packets(handle);

	start_iso.cycle = start_on_cycle;
	start_iso.tags =
		tag_mask == -1 ? FW_CDEV_ISO_CONTEXT_MATCH_ALL_TAGS : tag_mask;
	/* sync is documented as 'not used' */
	start_iso.sync = 0;
	start_iso.handle = 0;

	return ioctl(handle->iso.fd, FW_CDEV_IOC_START_ISO, &start_iso);
}

static int handle_iso_event(raw1394handle_t handle,
			    struct epoll_closure *closure, __uint32_t events)
{
	struct fw_cdev_event_iso_interrupt *interrupt;
	int len;

	len = read(handle->iso.fd, handle->buffer, sizeof handle->buffer);
	if (len < 0)
		return -1;

	interrupt = (struct fw_cdev_event_iso_interrupt *) handle->buffer;
	if (interrupt->type != FW_CDEV_EVENT_ISO_INTERRUPT)
		return 0;

	switch (handle->iso.type) {
	case FW_CDEV_ISO_CONTEXT_TRANSMIT:
		handle->iso.packet_count -= handle->iso.irq_interval;
		return queue_xmit_packets(handle, handle->iso.buf_packets);
	case FW_CDEV_ISO_CONTEXT_RECEIVE:
		return flush_recv_packets(handle, interrupt);
	default:
		/* Doesn't happen. */
		return -1;
	}
}

int raw1394_iso_xmit_write(raw1394handle_t handle, unsigned char *data,
			   unsigned int len, unsigned char tag,
			   unsigned char sy)
{
	struct fw_cdev_queue_iso queue_iso;
	struct fw_cdev_start_iso start_iso;
	struct fw_cdev_iso_packet *p;

	if (len > handle->iso.max_packet_size) {
		errno = EINVAL;
		return -1;
	}

	/* Block until we have space for another packet. */
	while (handle->iso.packet_count + handle->iso.irq_interval >
	       handle->iso.buf_packets)
		raw1394_loop_iterate(handle);
		
	memcpy(handle->iso.head, data, len);
	if (queue_packet(handle, len, 0, tag, sy) < 0)
		return -1;

	/* Start the streaming if it's not already running and if
	 * we've buffered up enough packets. */
	if (handle->iso.prebuffer > 0 &&
	    handle->iso.packet_count >= handle->iso.prebuffer) {
		/* Set this to 0 to indicate that we're running. */
		handle->iso.prebuffer = 0;
		start_iso.cycle  = handle->iso.start_on_cycle;
		start_iso.handle = 0;

		len = ioctl(handle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (len < 0)
			return len;
	}

	return 0;
}

int raw1394_iso_xmit_sync(raw1394handle_t handle)
{
	struct fw_cdev_iso_packet skip;
	struct fw_cdev_queue_iso queue_iso;
	int len;

	skip.control = FW_CDEV_ISO_INTERRUPT | FW_CDEV_ISO_SKIP;
	queue_iso.packets = ptr_to_u64(&skip);
	queue_iso.size    = sizeof skip;
	queue_iso.data    = 0;
	queue_iso.handle  = 0;

	len = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
	if (len < 0)
		return -1;

	/* Now that we've queued the skip packet, we'll get an
	 * interrupt when the transmit buffer is flushed, so all we do
	 * here is wait. */
	while (handle->iso.packet_count > 0)
		raw1394_loop_iterate(handle);

	/* The iso mainloop thinks that interrutps indicate another
	 * irq_interval number of packets was sent, so the skip
	 * interrupt makes it go out of whack.  We just reset it. */
	handle->iso.head = handle->iso.buffer;
	handle->iso.tail = handle->iso.buffer;
	handle->iso.first_payload = handle->iso.buffer;
	handle->iso.packet_phase = 0;
	handle->iso.packet_count = 0;

	return 0;
}

int raw1394_iso_recv_flush(raw1394handle_t handle)
{
	/* FIXME: huh, we'll need kernel support here... */

	return 0;
}

static unsigned int
round_to_power_of_two(unsigned int value)
{
	unsigned int pot;

	pot = 1;
	while (pot < value)
		pot <<= 1;

	return pot;
}

static int
iso_init(raw1394handle_t handle, int type,
	 raw1394_iso_xmit_handler_t xmit_handler,
	 raw1394_iso_recv_handler_t recv_handler,
	 unsigned int buf_packets,
	 unsigned int max_packet_size,
	 unsigned char channel,
	 enum raw1394_iso_speed speed,
	 int irq_interval)
{
	struct fw_cdev_create_iso_context create;
	struct epoll_event ep;
	int retval, prot;

	if (handle->iso.fd != -1) {
		errno = EBUSY;
		return -1;
	}

	switch (type) {
	case FW_CDEV_ISO_CONTEXT_TRANSMIT:
		prot = PROT_READ | PROT_WRITE;
		break;
	case FW_CDEV_ISO_CONTEXT_RECEIVE:
		prot = PROT_READ;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	handle->iso.type = type;
	if (irq_interval < 0)
		handle->iso.irq_interval = 256;
	else
		handle->iso.irq_interval = irq_interval;
	handle->iso.xmit_handler = xmit_handler;
	handle->iso.recv_handler = recv_handler;
	handle->iso.buf_packets = buf_packets;
	handle->iso.max_packet_size = round_to_power_of_two(max_packet_size);
	handle->iso.packet_phase = 0;
	handle->iso.packet_count = 0;
	handle->iso.packets =
		malloc(handle->iso.irq_interval * sizeof handle->iso.packets[0]);
	if (handle->iso.packets == NULL)
		return -1;

	handle->iso.fd = open(handle->local_filename, O_RDWR);
	if (handle->iso.fd < 0) {
		free(handle->iso.packets);
		return -1;
	}

	handle->iso.closure.func = handle_iso_event;
	ep.events = EPOLLIN;
	ep.data.ptr = &handle->iso.closure;
	if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD,
		      handle->iso.fd, &ep) < 0) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		return -1;
	}

	create.type = type;
	create.channel = channel;
	create.speed = speed;
	create.header_size = 4;

	retval = ioctl(handle->iso.fd,
		       FW_CDEV_IOC_CREATE_ISO_CONTEXT, &create);
	if (retval < 0) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		return retval;
	}

	handle->iso.buffer =
		mmap(NULL, buf_packets * max_packet_size,
		     prot, MAP_SHARED, handle->iso.fd, 0);

	if (handle->iso.buffer == MAP_FAILED) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		return -1;
	}

	handle->iso.buffer_end = handle->iso.buffer + 
		buf_packets * max_packet_size;
	handle->iso.head = handle->iso.buffer;
	handle->iso.tail = handle->iso.buffer;
	handle->iso.first_payload = handle->iso.buffer;

	return 0;
}

int raw1394_iso_xmit_init(raw1394handle_t handle,
			  raw1394_iso_xmit_handler_t handler,
			  unsigned int buf_packets,
			  unsigned int max_packet_size,
			  unsigned char channel,
			  enum raw1394_iso_speed speed,
			  int irq_interval)
{
	return iso_init(handle, FW_CDEV_ISO_CONTEXT_TRANSMIT,
			handler, NULL, buf_packets, max_packet_size,
			channel, speed, irq_interval);
}

int raw1394_iso_recv_init(raw1394handle_t handle,
			  raw1394_iso_recv_handler_t handler,
			  unsigned int buf_packets,
			  unsigned int max_packet_size,
			  unsigned char channel,
			  enum raw1394_iso_dma_recv_mode mode,
			  int irq_interval)
{
	return iso_init(handle, FW_CDEV_ISO_CONTEXT_RECEIVE,
			NULL, handler, buf_packets, max_packet_size,
			channel, 0, irq_interval);
}

int raw1394_iso_multichannel_recv_init(raw1394handle_t handle,
				       raw1394_iso_recv_handler_t handler,
				       unsigned int buf_packets,
				       unsigned int max_packet_size,
				       int irq_interval)
{
	/* FIXME: gah */
	errno = ENOSYS;
	return -1;
}

int raw1394_iso_recv_listen_channel(raw1394handle_t handle,
				    unsigned char channel)
{
	/* FIXME: multichannel */
	errno = ENOSYS;
	return -1;
}

int raw1394_iso_recv_unlisten_channel(raw1394handle_t handle,
				      unsigned char channel)
{
	/* FIXME: multichannel */
	errno = ENOSYS;
	return -1;
}

int raw1394_iso_recv_set_channel_mask(raw1394handle_t handle, u_int64_t mask)
{
	/* FIXME: multichannel */
	errno = ENOSYS;
	return -1;
}

void raw1394_iso_stop(raw1394handle_t handle)
{
	struct fw_cdev_stop_iso stop_iso;

	stop_iso.handle = 0;
	ioctl(handle->iso.fd, FW_CDEV_IOC_STOP_ISO);

	handle->iso.head = handle->iso.buffer;
	handle->iso.tail = handle->iso.buffer;
	handle->iso.first_payload = handle->iso.buffer;
	handle->iso.packet_phase = 0;
	handle->iso.packet_count = 0;
}

void raw1394_iso_shutdown(raw1394handle_t handle)
{
	munmap(handle->iso.buffer,
	       handle->iso.buf_packets * handle->iso.max_packet_size);
	close(handle->iso.fd);
	free(handle->iso.packets);
}
