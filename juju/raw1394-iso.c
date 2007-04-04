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

static enum raw1394_iso_disposition
queue_xmit_packets(raw1394handle_t handle)
{
	struct fw_cdev_iso_packet *p = handle->iso.packets;
	struct fw_cdev_queue_iso queue_iso;
	enum raw1394_iso_disposition d;
	unsigned int len, dropped;
	unsigned char tag, sy, *first_payload;
	int cycle, i;

	first_payload = handle->iso.head;
	for (i = 0; i < handle->iso.irq_interval; i++) {
		cycle = -1;
		dropped = 0;

		if (handle->iso.head + handle->iso.max_packet_size >
		    handle->iso.buffer_end) {
			handle->iso.head = handle->iso.buffer;
			break;
		}

		d = handle->iso.xmit_handler(handle, handle->iso.head,
					     &len, &tag, &sy, cycle, dropped);
		if (d != RAW1394_ISO_OK)
			break;

		p->payload_length = len;
		p->interrupt =
			handle->iso.packet_phase == handle->iso.irq_interval - 1;
		p->skip = 0;
		p->tag = tag;
		p->sy = sy;
		p->header_length = 0;

		handle->iso.head += len;
		handle->iso.packet_count++;
		handle->iso.packet_phase++;

		if (handle->iso.packet_phase == handle->iso.irq_interval)
			handle->iso.packet_phase = 0;
	}

	queue_iso.packets = ptr_to_u64(handle->iso.packets);
	queue_iso.size    = i * sizeof handle->iso.packets[0];
	queue_iso.data    = ptr_to_u64(first_payload);

	len = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
	if (len < 0)
		return RAW1394_ISO_ERROR;

	return d;
}

static int
flush_xmit_packets(raw1394handle_t handle, int limit)
{
	enum raw1394_iso_disposition d;
	int len;

	if (handle->iso.xmit_handler == NULL)
		return 0;

	if (limit < handle->iso.irq_interval)
		limit = handle->iso.irq_interval;

	while (handle->iso.packet_count + handle->iso.irq_interval <= limit) {
		d = queue_xmit_packets(handle);
		switch (d) {
		case RAW1394_ISO_DEFER:
		case RAW1394_ISO_AGAIN:
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

	flush_xmit_packets(handle, prebuffer_packets);

	if (handle->iso.prebuffer <= handle->iso.packet_count) {
		start_iso.cycle = start_on_cycle;

		retval = ioctl(handle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (retval < 0)
			return retval;
	}

	return flush_xmit_packets(handle, handle->iso.buf_packets);
}

static int
queue_recv_packets(raw1394handle_t handle)
{
	struct fw_cdev_queue_iso queue_iso;
	struct fw_cdev_iso_packet *p = handle->iso.packets;
	unsigned int len;
	unsigned char *first_payload;
	int i;

	first_payload = handle->iso.head;
	for (i = 0; i < handle->iso.irq_interval; i++, p++) {
		if (handle->iso.head + handle->iso.max_packet_size >
		    handle->iso.buffer_end) {
			handle->iso.head = handle->iso.buffer;
			break;
		}

		p->payload_length = handle->iso.max_packet_size;
		p->interrupt = handle->iso.packet_phase == handle->iso.irq_interval - 1;
		p->skip = 0;
		p->tag = 0;
		p->sy = 0;
		p->header_length = 4;

		handle->iso.head += handle->iso.max_packet_size;
		handle->iso.packet_count++;
		handle->iso.packet_phase++;

		if (handle->iso.packet_phase == handle->iso.irq_interval)
			handle->iso.packet_phase = 0;
	}

	queue_iso.packets = ptr_to_u64(handle->iso.packets);
	queue_iso.size    = i * sizeof handle->iso.packets[0];
	queue_iso.data    = ptr_to_u64(first_payload);

	len = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
	if (len < 0)
		return -1;

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
	unsigned char *data;

	p = interrupt->header;
	end = (void *) interrupt->header + interrupt->header_length;
	cycle = interrupt->cycle;
	dropped = 0;

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
		if (handle->iso.tail == handle->iso.buffer_end)
			handle->iso.tail = handle->iso.buffer;
	}

	switch (d) {
	case RAW1394_ISO_OK:
	case RAW1394_ISO_DEFER:
		break;
		
	case RAW1394_ISO_ERROR:
		return -1;

	case RAW1394_ISO_STOP:
		raw1394_iso_stop(handle);
		return 0;		
	}

	while (handle->iso.packet_count + handle->iso.irq_interval <=
	       handle->iso.buf_packets)
		queue_recv_packets(handle);

	return 0;
}

int raw1394_iso_recv_start(raw1394handle_t handle, int start_on_cycle,
			   int tag_mask, int sync)
{
	struct fw_cdev_start_iso start_iso;

	while (handle->iso.packet_count + handle->iso.irq_interval <=
	       handle->iso.buf_packets)
		queue_recv_packets(handle);

	start_iso.cycle = start_on_cycle;
	start_iso.tags =
		tag_mask == -1 ? FW_CDEV_ISO_CONTEXT_MATCH_ALL_TAGS : tag_mask;
	/* sync is documented as 'not used' */
	start_iso.sync = 0;

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
		return flush_xmit_packets(handle, handle->iso.buf_packets);
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

	{
		int i;
		__u32 *p = (__u32 *) data;

		for (i = 0; i < 10; i++)
			fprintf(stderr, "0x%08x ", p[i]);
		fprintf(stderr, "\n");
	}

	if (len > handle->iso.max_packet_size) {
		errno = EINVAL;
		return -1;
	}

	/* Block until we have space for another packet. */
	while (handle->iso.packet_count + handle->iso.irq_interval >
	       handle->iso.buf_packets)
		raw1394_loop_iterate(handle);

	p = &handle->iso.packets[handle->iso.packet_header_index];
	p->payload_length = len;
	p->interrupt =
		handle->iso.packet_phase == handle->iso.irq_interval - 1;
	p->skip = 0;
	p->tag = tag;
	p->sy = sy;
	p->header_length = 0;
		
	memcpy(handle->iso.head, data, len);

	handle->iso.head += len;
	handle->iso.packet_count++;
	handle->iso.packet_phase++;
	handle->iso.packet_header_index++;

	if (handle->iso.packet_phase == handle->iso.irq_interval)
		handle->iso.packet_phase = 0;

	if (handle->iso.head + handle->iso.max_packet_size > handle->iso.buffer_end)
		handle->iso.head = handle->iso.buffer;

	/* Queue the packets in the kernel if we filled up the packets
	 * array or wrapped the payload buffer. */
	if (handle->iso.packet_header_index == handle->iso.irq_interval ||
	    handle->iso.head == handle->iso.buffer) {
		queue_iso.packets = ptr_to_u64(handle->iso.packets);
		queue_iso.size    = handle->iso.packet_header_index * sizeof handle->iso.packets[0];
		queue_iso.data    = ptr_to_u64(handle->iso.first_payload);
		handle->iso.packet_header_index = 0;
		handle->iso.first_payload = handle->iso.head;

		len = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
		if (len < 0)
			return -1;
	}

	/* Start the streaming if it's not already running and if
	 * we've buffered up enough packets. */
	if (handle->iso.prebuffer > 0 &&
	    handle->iso.packet_count >= handle->iso.prebuffer) {
		/* Set this to 0 to indicate that we're running. */
		handle->iso.prebuffer = 0;
		start_iso.cycle = handle->iso.start_on_cycle;

		len = ioctl(handle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (len < 0)
			return len;
	}

	return 0;
}

int raw1394_iso_xmit_sync(raw1394handle_t handle)
{
	/* FIXME: queue a skip packet and wait for that interrupt. */

	return 0;
}

int raw1394_iso_recv_flush(raw1394handle_t handle)
{
	/* FIXME: huh, we'll need kernel support here... */

	return 0;
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

	handle->iso.type = type;
	if (irq_interval < 0)
		handle->iso.irq_interval = 256;
	else
		handle->iso.irq_interval = irq_interval;
	handle->iso.xmit_handler = xmit_handler;
	handle->iso.recv_handler = recv_handler;
	handle->iso.buf_packets = buf_packets;
	handle->iso.max_packet_size = max_packet_size;
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

	switch (type) {
	case FW_CDEV_ISO_CONTEXT_TRANSMIT:
		prot = PROT_READ | PROT_WRITE;
		break;
	case FW_CDEV_ISO_CONTEXT_RECEIVE:
		prot = PROT_READ;
		break;
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
