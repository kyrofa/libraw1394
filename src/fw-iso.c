/*						-*- c-basic-offset: 8 -*-
 *
 * fw-iso.c -- Emulation of the raw1394 rawiso API on the firewire stack
 *
 * Copyright (C) 2007  Kristian Hoegsberg <krh@bitplanet.net>
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 */

#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "fw.h"
#include "raw1394_private.h"

static int calculate_start_cycle(fw_handle_t handle)
{
	int cycle;
	u_int32_t cycle_timer;
	u_int64_t local_time;

	cycle = handle->iso.start_on_cycle;
	if (cycle < 0)
		return cycle;

	/* libraw1394's cycle is always mod 8000 */
	cycle &= 0x1fff;

	/* get the seconds from the current value of the cycle timer */
	if (fw_read_cycle_timer(handle, &cycle_timer, &local_time) != 0)
		return cycle;
	cycle += (cycle_timer & 0xfe000000) >> 12;

	/*
	 * For compatibility with raw1394, add one second
	 * "to give some extra time for DMA to start".
	 * TODO: are there still races due to cycle rollover?
	 */
	cycle += 1 << 13;

	return cycle & 0x7fff;
}

static int
queue_packet(fw_handle_t handle,
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

	/* queue each packet individually */
	if (1) {
		queue_iso.packets = ptr_to_u64(handle->iso.packets);
		queue_iso.size    = handle->iso.packet_index * sizeof handle->iso.packets[0];
		queue_iso.data    = ptr_to_u64(handle->iso.first_payload);
		queue_iso.handle  = handle->iso.kernel_handle;
		handle->iso.packet_index = 0;
		handle->iso.first_payload = handle->iso.head;

		err = ioctl(handle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
		if (err < 0)
			return -1;
	}
	return 0;
}

static int
queue_xmit_packets(raw1394handle_t handle, int limit, int cycle)
{
	fw_handle_t fwhandle = handle->mode.fw;
	enum raw1394_iso_disposition d;
	unsigned char tag, sy;
	unsigned int len;
	unsigned int dropped = 0;

	if (fwhandle->iso.xmit_handler == NULL)
		return 0;

	while (fwhandle->iso.packet_count < limit) {

		d = fwhandle->iso.xmit_handler(handle, fwhandle->iso.head,
					     &len, &tag, &sy, cycle, dropped);

		switch (d) {
		case RAW1394_ISO_OK:
			queue_packet(fwhandle, len, 0, tag, sy);
			if (cycle >= 0) {
				cycle++;
				if (cycle >= 8000)
					cycle %= 8000;
			}
			break;
		case RAW1394_ISO_DEFER:
		case RAW1394_ISO_AGAIN:
		default:
			return 0;
		case RAW1394_ISO_ERROR:
			return -1;
		case RAW1394_ISO_STOP:
			fw_iso_stop(fwhandle);
			return 0;
		}
	}

	return 0;
}

int fw_iso_xmit_start(raw1394handle_t handle, int start_on_cycle,
			   int prebuffer_packets)
{
	fw_handle_t fwhandle = handle->mode.fw;
	struct fw_cdev_start_iso start_iso;
	int retval;

	if (prebuffer_packets == -1)
		prebuffer_packets = fwhandle->iso.irq_interval;

	fwhandle->iso.prebuffer = prebuffer_packets;
	fwhandle->iso.start_on_cycle = start_on_cycle;

	retval = queue_xmit_packets(handle, prebuffer_packets, start_on_cycle);
	if (retval)
		return -1;

	if (start_on_cycle >= 0) {
		int tmp;

		tmp = start_on_cycle + prebuffer_packets;
		tmp %= 8000;
		retval = queue_xmit_packets(handle, fwhandle->iso.buf_packets, tmp);
	} else {
		retval = queue_xmit_packets(handle, fwhandle->iso.buf_packets, -1);
	}
	if (retval)
		return -1;

	if (fwhandle->iso.prebuffer <= fwhandle->iso.packet_count) {
		start_iso.sync   = 0; /* unused */
		start_iso.tags   = 0; /* unused */
		start_iso.cycle  = calculate_start_cycle(fwhandle);
		start_iso.handle = fwhandle->iso.kernel_handle;

		retval = ioctl(fwhandle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (retval < 0)
			return retval;
	}

	fwhandle->iso.state = ISO_ACTIVE;

	return 0;
}

static inline int abi_has_iso_rx_timestamps(fw_handle_t handle)
{
	return handle->abi_version >= 2;
}

static inline int recv_header_length(fw_handle_t handle)
{
	return abi_has_iso_rx_timestamps(handle) ? 8 : 4;
}

static int
queue_recv_packets(fw_handle_t handle)
{
	while (handle->iso.packet_count < handle->iso.buf_packets)
		queue_packet(handle, handle->iso.max_packet_size,
			     recv_header_length(handle), 0, 0);
	return 0;
}

static void extract_packet_header(quadlet_t data, quadlet_t *header, unsigned int *len, unsigned char *channel, unsigned char *tag, unsigned char *sy)
{
	*header = data;
	*len = *header >> 16;
	*tag = (*header >> 14) & 0x3;
	*channel = (*header >> 8) & 0x3f;
	*sy = *header & 0x0f;
}

static void extract_mc_packet_header(quadlet_t *data, quadlet_t *header, unsigned int *len, unsigned char *channel, unsigned char *tag, unsigned char *sy, unsigned int *aligned_len, unsigned int *total_packet_size)
{
	extract_packet_header(le32_to_cpu(*data), header, len, channel, tag, sy);

	// Total package size is len (rounded up to a multiple of 4) + 4 for the timestamp at the end
	*aligned_len = (*len + 3) & ~0x03;
	*total_packet_size = *aligned_len + 4;
}

static unsigned char *end_of_current_buffer_section(fw_handle_t fwhandle) {
       unsigned char *section_end = fwhandle->iso.current_buffer_section + fwhandle->iso.max_packet_size;
       if (section_end > fwhandle->iso.buffer_end)
               section_end = fwhandle->iso.buffer_end;
       return section_end;
}

static enum raw1394_iso_disposition process_sc_packet(raw1394handle_t handle, quadlet_t **p, unsigned int *cycle)
{
	fw_handle_t fwhandle = handle->mode.fw;
	enum raw1394_iso_disposition d;
	quadlet_t header;
	unsigned int len;
	unsigned char channel, tag, sy;

	extract_packet_header(be32_to_cpu(*(*p)++), &header, &len, &channel, &tag, &sy);

	if (abi_has_iso_rx_timestamps(fwhandle))
		*cycle = be32_to_cpu(*(*p)++) & 0x1fff;
	else {
		(*cycle)++;
		if (*cycle >= 8000)
			*cycle -= 8000;
	}

	d = fwhandle->iso.recv_handler(handle, fwhandle->iso.tail, len, channel, tag, sy, *cycle, 0);

	// OK means "processed that one, give me more", and DEFER means "processed
	// that one, wait until I ask to give me more." Both OK and DEFER, then,
	// indicate that this particular packet was processed, so we should move
	// the tail past it unless we encountered some sort of error.
	if (d != RAW1394_ISO_OK && d != RAW1394_ISO_DEFER)
		return d;

	fwhandle->iso.tail += fwhandle->iso.max_packet_size;
	fwhandle->iso.packet_count--;

	if (fwhandle->iso.tail + fwhandle->iso.max_packet_size > fwhandle->iso.buffer_end)
		fwhandle->iso.tail = fwhandle->iso.buffer;

	return d;
}

static enum raw1394_iso_disposition process_mc_packet(raw1394handle_t handle, quadlet_t **p, unsigned int *cycle)
{
	fw_handle_t fwhandle = handle->mode.fw;
	enum raw1394_iso_disposition d = RAW1394_ISO_OK;
	quadlet_t header;
	unsigned int len, aligned_len, total_packet_size;
	unsigned char channel, tag, sy;

	// If we're currently operating on a split packet, the first thing we need to do is
	// complete the packet in our separate buffer
	if (fwhandle->iso.packet_split_state == PACKET_IS_SPLIT) {
		quadlet_t *split_p = (void *) fwhandle->iso.split_packet_buffer;

		extract_mc_packet_header(split_p++, &header, &len, &channel, &tag, &sy, &aligned_len, &total_packet_size);
		unsigned int remaining_length = (unsigned char *)*p - fwhandle->iso.buffer;

		memcpy(fwhandle->iso.split_packet_buffer + 4 + (total_packet_size-remaining_length), fwhandle->iso.buffer, remaining_length);

		*cycle = le32_to_cpu(*(split_p+aligned_len/4)) & 0x1fff;
		d = fwhandle->iso.recv_handler(handle, (unsigned char *) split_p, len, channel, tag, sy, *cycle, 0);
		fwhandle->iso.packet_split_state = PACKET_NOT_SPLIT;
	} else {
		extract_mc_packet_header((*p)++, &header, &len, &channel, &tag, &sy, &aligned_len, &total_packet_size);
		unsigned char *next_packet = ((unsigned char *) *p) + total_packet_size;

		// Make sure there's enough room for this packet. If there's not, don't call
		// the recv handler-- copy what's there into the split packet buffer, move
		// back to the beginning of the buffer, and return OK. We'll read the rest
		// of the packet during the next iteration.
		if (next_packet <= fwhandle->iso.valid_data_end) {
			*cycle = le32_to_cpu(*(*p+aligned_len/4)) & 0x1fff;
			d = fwhandle->iso.recv_handler(handle, (unsigned char *) *p, len, channel, tag, sy, *cycle, 0);

			// OK means "processed that one, give me more", and DEFER means "processed
			// that one, wait until I ask to give me more." Both OK and DEFER, then,
			// indicate that this particular packet was processed, so we should move
			// the tail past it unless we encountered some sort of error.
			if (d != RAW1394_ISO_OK && d != RAW1394_ISO_DEFER)
				return d;

			fwhandle->iso.tail = next_packet;
		} else {
			// Not enough room for this packet: defer
			d = RAW1394_ISO_DEFER;
		}

		if (next_packet >= fwhandle->iso.buffer_end) {
			// Wrap around back to the beginning of the ring buffer
			unsigned int bytes_available = fwhandle->iso.buffer_end-fwhandle->iso.tail;
			unsigned int buffer_offset = 0;

			if (bytes_available > 0) {
				fwhandle->iso.packet_split_state = PACKET_IS_SPLIT;
				memcpy(fwhandle->iso.split_packet_buffer, fwhandle->iso.tail, bytes_available);
				buffer_offset = total_packet_size + 4 - bytes_available; // +4 for the header
			}
			fwhandle->iso.tail = fwhandle->iso.buffer + buffer_offset;
			fwhandle->iso.current_buffer_section = fwhandle->iso.buffer;
			fwhandle->iso.packet_count--;

			// We know that we've read all the way to the end of the buffer, so
			// invalidate the entire buffer.
			fwhandle->iso.valid_data_end = fwhandle->iso.buffer;
		}

		while (fwhandle->iso.tail >= end_of_current_buffer_section(fwhandle)) {
			// In multichannel, the packet count isn't really a count of packets,
			// but a count of buffer sections. Which means the only time we can
			// decrement this counter (and thus queue up another section) is when
			// we have completely finished processing one section. Otherwise
			// we'll write faster than we're reading.
			fwhandle->iso.current_buffer_section += fwhandle->iso.max_packet_size;
			fwhandle->iso.packet_count--;
		}
	}

	return d;
}

static int handle_disposition(fw_handle_t fwhandle, enum raw1394_iso_disposition d)
{
	switch (d) {
	case RAW1394_ISO_OK:
	case RAW1394_ISO_DEFER:
	default:
		break;

	case RAW1394_ISO_ERROR:
		return -1;

	case RAW1394_ISO_STOP:
		fw_iso_stop(fwhandle);
		return 0;
	}

	queue_recv_packets(fwhandle);

	return 0;
}

static enum raw1394_iso_disposition
flush_recv_packets_mc(raw1394handle_t handle,
                      struct fw_cdev_event_iso_interrupt_mc *interrupt)
{
	fw_handle_t fwhandle = handle->mode.fw;
	enum raw1394_iso_disposition d;
	quadlet_t *p, *end;
	unsigned int cycle;

	unsigned char *completed = fwhandle->iso.buffer + interrupt->completed;
	if (completed > fwhandle->iso.valid_data_end)
		fwhandle->iso.valid_data_end = completed;

	p = (void *) fwhandle->iso.tail;
	end = (void *) fwhandle->iso.valid_data_end;

	cycle = 0;
	d = RAW1394_ISO_OK;

	while (p < end) {
		d = process_mc_packet(handle, &p, &cycle);

		if (d != RAW1394_ISO_OK)
			break;

		p = (void *) fwhandle->iso.tail;
	}

	return handle_disposition(fwhandle, d);
}

static enum raw1394_iso_disposition
flush_recv_packets(raw1394handle_t handle,
		   struct fw_cdev_event_iso_interrupt *interrupt)
{
	fw_handle_t fwhandle = handle->mode.fw;
	enum raw1394_iso_disposition d;
	quadlet_t *p, *end;
	unsigned int cycle;

	p = interrupt->header;
	end = (void *) interrupt->header + interrupt->header_length;
	/*
	 * This is bogus, but it's the best we can do without accurate
	 * timestamps.  Assume that the first packet was received
	 * {number of packets} before the cycle recorded in the interrupt
	 * event, and that each subsequent packet was received one cycle
	 * later.  This also assumes that the interrupt event happened
	 * immediately after the last packet was received.
	 */
	if (!abi_has_iso_rx_timestamps(fwhandle)) {
		cycle = interrupt->cycle;
		cycle &= 0x1fff;
		cycle += 8000;
		cycle -= interrupt->header_length / 4;
	}

	d = RAW1394_ISO_OK;

	while (p < end) {
		d = process_sc_packet(handle, &p, &cycle);
		if (d != RAW1394_ISO_OK)
			/* FIXME: we need to save the headers so we
			 * can restart this loop. */
			break;
	}

	return handle_disposition(fwhandle, d);
}

int fw_iso_recv_start(fw_handle_t handle, int start_on_cycle,
			   int tag_mask, int sync)
{
	struct fw_cdev_start_iso start_iso;

	queue_recv_packets(handle);

	handle->iso.start_on_cycle = start_on_cycle;
	start_iso.cycle = calculate_start_cycle(handle);
	start_iso.tags =
		tag_mask == -1 ? FW_CDEV_ISO_CONTEXT_MATCH_ALL_TAGS : tag_mask;
	/* sync is documented as 'not used' */
	start_iso.sync = 0;
	start_iso.handle = handle->iso.kernel_handle;

	if (ioctl(handle->iso.fd, FW_CDEV_IOC_START_ISO, &start_iso))
		return -1;
	else
		handle->iso.state = ISO_ACTIVE;

	return 0;
}

static int handle_iso_event(raw1394handle_t handle,
			    struct epoll_closure *closure, uint32_t events)
{
	fw_handle_t fwhandle = handle->mode.fw;
	int len;
	struct pollfd pollFd;

	pollFd.fd = fwhandle->iso.fd;
	pollFd.events = POLLIN;

	// Don't read from this fd unless we know it has data. Opening this device in
	// non-blocking mode doesn't work (i.e. it can still block).
	if (poll(&pollFd, 1, 0) > 0) {
		len = read(fwhandle->iso.fd, fwhandle->buffer, sizeof fwhandle->buffer);
		if (len < 0) return -1;
	}

	switch (fwhandle->iso.type) {
	case FW_CDEV_ISO_CONTEXT_TRANSMIT:
	{
		int cycle;

		struct fw_cdev_event_iso_interrupt *interrupt = (struct fw_cdev_event_iso_interrupt *) fwhandle->buffer;
		if (interrupt->type != FW_CDEV_EVENT_ISO_INTERRUPT)
			return 0;

		/* Check whether the ABI version provides iso tx timestamps. */
		if (interrupt->header_length) {
			fwhandle->iso.packet_count -= interrupt->header_length/4;
			/*
			 * Take the cycle of the last packet transmitted, add
			 * the number of packets currently queued, plus one, and
			 * that's the cycle number of the next packet to ask
			 * for.
			 */
			cycle = be32_to_cpu(interrupt->header[interrupt->header_length/4 - 1]);
			cycle &= 0x1fff;
		} else {
			fwhandle->iso.packet_count -= fwhandle->iso.irq_interval;
			/*
			 * Bogusly faking it again.  Assume that the last packet
			 * transmitted was transmitted on interrupt->cycle.
			 */
			cycle = interrupt->cycle;
		}
		cycle += fwhandle->iso.packet_count;
		cycle++;
		cycle %= 8000;
		return queue_xmit_packets(handle, fwhandle->iso.buf_packets, cycle);
	}
	case FW_CDEV_ISO_CONTEXT_RECEIVE:
	{
		struct fw_cdev_event_iso_interrupt *interrupt = (struct fw_cdev_event_iso_interrupt *) fwhandle->buffer;
		if (interrupt->type != FW_CDEV_EVENT_ISO_INTERRUPT)
			return 0;

		return flush_recv_packets(handle, interrupt);
	}
	case FW_CDEV_ISO_CONTEXT_RECEIVE_MULTICHANNEL:
	{
		struct fw_cdev_event_iso_interrupt_mc *interrupt = (struct fw_cdev_event_iso_interrupt_mc *) fwhandle->buffer;
		if (interrupt->type != FW_CDEV_EVENT_ISO_INTERRUPT_MULTICHANNEL)
			return 0;

		return flush_recv_packets_mc(handle, interrupt);
	}
	default:
		/* Doesn't happen. */
		return -1;
	}
}

int fw_iso_xmit_write(raw1394handle_t handle, unsigned char *data,
			   unsigned int len, unsigned char tag,
			   unsigned char sy)
{
	fw_handle_t fwhandle = handle->mode.fw;
	struct fw_cdev_start_iso start_iso;
	int retval;

	if (len > fwhandle->iso.max_packet_size) {
		errno = EINVAL;
		return -1;
	}

	/* Block until we have space for another packet. */
	while (fwhandle->iso.packet_count + fwhandle->iso.irq_interval >
	       fwhandle->iso.buf_packets)
		fw_loop_iterate(handle);

	memcpy(fwhandle->iso.head, data, len);
	if (queue_packet(fwhandle, len, 0, tag, sy) < 0)
		return -1;

	/* Start the streaming if it's not already running and if
	 * we've buffered up enough packets. */
	if (fwhandle->iso.prebuffer > 0 &&
	    fwhandle->iso.packet_count >= fwhandle->iso.prebuffer) {
		/* Set this to 0 to indicate that we're running. */
		fwhandle->iso.prebuffer = 0;
		start_iso.cycle  = calculate_start_cycle(fwhandle);
		start_iso.handle = fwhandle->iso.kernel_handle;

		retval = ioctl(fwhandle->iso.fd,
			       FW_CDEV_IOC_START_ISO, &start_iso);
		if (retval < 0)
			return retval;
	}

	return 0;
}

int fw_iso_xmit_sync(raw1394handle_t handle)
{
	fw_handle_t fwhandle = handle->mode.fw;
	struct fw_cdev_iso_packet skip;
	struct fw_cdev_queue_iso queue_iso;
	int len;

	skip.control = FW_CDEV_ISO_INTERRUPT | FW_CDEV_ISO_SKIP;
	queue_iso.packets = ptr_to_u64(&skip);
	queue_iso.size    = sizeof skip;
	queue_iso.data    = 0;
	queue_iso.handle  = fwhandle->iso.kernel_handle;

	len = ioctl(fwhandle->iso.fd, FW_CDEV_IOC_QUEUE_ISO, &queue_iso);
	if (len < 0)
		return -1;

	/* Now that we've queued the skip packet, we'll get an
	 * interrupt when the transmit buffer is flushed, so all we do
	 * here is wait. */
	while (fwhandle->iso.packet_count > 0)
		fw_loop_iterate(handle);

	/* The iso mainloop thinks that interrutps indicate another
	 * irq_interval number of packets was sent, so the skip
	 * interrupt makes it go out of whack.  We just reset it. */
	fwhandle->iso.head = fwhandle->iso.buffer;
	fwhandle->iso.tail = fwhandle->iso.buffer;
	fwhandle->iso.first_payload = fwhandle->iso.buffer;
	fwhandle->iso.packet_phase = 0;
	fwhandle->iso.packet_count = 0;

	return 0;
}

int fw_iso_recv_flush(fw_handle_t handle)
{
	struct fw_cdev_flush_iso flush;

	flush.handle = handle->iso.kernel_handle;
	return ioctl(handle->iso.fd, FW_CDEV_IOC_FLUSH_ISO, &flush);
}

static int
iso_init(fw_handle_t handle, int type,
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
	int retval;

	if (handle->iso.fd != -1) {
		errno = EBUSY;
		return -1;
	}

	/* set irq_interval from < 1 to default values like ieee1394 rawiso */
	if (irq_interval < 0)
		irq_interval = buf_packets / 4;
	if (irq_interval == 0)
		irq_interval = 1;

	handle->iso.type = type;
	handle->iso.irq_interval = irq_interval;
	handle->iso.xmit_handler = xmit_handler;
	handle->iso.recv_handler = recv_handler;
	handle->iso.buf_packets = buf_packets;
	handle->iso.max_packet_size = max_packet_size;
	handle->iso.packet_phase = 0;
	handle->iso.packet_count = 0;
	handle->iso.packets =
		malloc(handle->iso.irq_interval * sizeof handle->iso.packets[0]);
	if (handle->iso.packets == NULL) {
		errno = ENOMEM;
		return -1;
	}

	handle->iso.fd = open(handle->iso.filename, O_RDWR);
	if (handle->iso.fd < 0) {
		free(handle->iso.packets);
		handle->iso.packets = NULL;
		return -1;
	}

	handle->iso.closure.func = handle_iso_event;
	memset(&ep, 0, sizeof(ep));
	ep.events = EPOLLIN;
	ep.data.ptr = &handle->iso.closure;
	if (epoll_ctl(handle->epoll_fd, EPOLL_CTL_ADD,
		      handle->iso.fd, &ep) < 0) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		handle->iso.packets = NULL;
		return -1;
	}

	memset(&create, 0, sizeof(create));
	create.type = type;
	create.channel = channel;
	create.speed = speed;
	create.header_size = recv_header_length(handle);

	retval = ioctl(handle->iso.fd,
		       FW_CDEV_IOC_CREATE_ISO_CONTEXT, &create);
	if (retval < 0) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		handle->iso.packets = NULL;
		return retval;
	}
	handle->iso.kernel_handle = create.handle;

	handle->iso.buffer =
		mmap(NULL, buf_packets * handle->iso.max_packet_size,
		     PROT_READ | PROT_WRITE, MAP_SHARED, handle->iso.fd, 0);

	if (handle->iso.buffer == MAP_FAILED) {
		close(handle->iso.fd);
		free(handle->iso.packets);
		handle->iso.packets = NULL;
		return -1;
	}

	handle->iso.buffer_end = handle->iso.buffer +
		buf_packets * handle->iso.max_packet_size;
	handle->iso.head = handle->iso.buffer;
	handle->iso.tail = handle->iso.buffer;
	handle->iso.first_payload = handle->iso.buffer;
	handle->iso.current_buffer_section = handle->iso.buffer;
	handle->iso.valid_data_end = handle->iso.buffer;
	handle->iso.state = ISO_STOPPED;

	handle->iso.packet_split_state = PACKET_NOT_SPLIT;
	handle->iso.split_packet_buffer = malloc(handle->iso.max_packet_size);
	if (handle->iso.split_packet_buffer == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

int fw_iso_xmit_init(fw_handle_t handle,
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

int fw_iso_recv_init(fw_handle_t handle,
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

int fw_iso_multichannel_recv_init(fw_handle_t handle,
				       raw1394_iso_recv_handler_t handler,
				       unsigned int buf_packets,
				       unsigned int max_packet_size,
				       int irq_interval)
{
	return iso_init(handle, FW_CDEV_ISO_CONTEXT_RECEIVE_MULTICHANNEL,
			NULL, handler, buf_packets, max_packet_size,
			-1, 0, irq_interval);
}

int fw_iso_recv_listen_channel(fw_handle_t handle,
				    unsigned char channel)
{
	/* kyrofa(07/27/22): there doesn't appear to be a corresponding ioctl for this */
	/* FIXME: multichannel */
	errno = ENOSYS;
	return -1;
}

int fw_iso_recv_unlisten_channel(fw_handle_t handle,
				      unsigned char channel)
{
	/* kyrofa(07/27/22): there doesn't appear to be a corresponding ioctl for this */
	/* FIXME: multichannel */
	errno = ENOSYS;
	return -1;
}

int fw_iso_recv_set_channel_mask(fw_handle_t handle, u_int64_t mask)
{
	struct fw_cdev_set_iso_channels channel_selection;
	memset(&channel_selection, 0, sizeof(channel_selection));
	channel_selection.channels = mask;

	return ioctl(handle->iso.fd, FW_CDEV_IOC_SET_ISO_CHANNELS, &channel_selection);
}

void fw_iso_stop(fw_handle_t handle)
{
	struct fw_cdev_stop_iso stop_iso;

	stop_iso.handle = handle->iso.kernel_handle;
	ioctl(handle->iso.fd, FW_CDEV_IOC_STOP_ISO, &stop_iso);

	handle->iso.head = handle->iso.buffer;
	handle->iso.tail = handle->iso.buffer;
	handle->iso.first_payload = handle->iso.buffer;
	handle->iso.packet_phase = 0;
	handle->iso.packet_count = 0;
	handle->iso.packet_index = 0;
	handle->iso.state = ISO_STOPPED;
}

void fw_iso_shutdown(fw_handle_t handle)
{
	if (handle->iso.packets == NULL)
		return;

	munmap(handle->iso.buffer,
	       handle->iso.buf_packets * handle->iso.max_packet_size);
	if (handle->iso.state != ISO_STOPPED)
		fw_iso_stop(handle);
	close(handle->iso.fd);
	free(handle->iso.packets);
	handle->iso.packets = NULL;
	handle->iso.fd = -1;
}

int fw_read_cycle_timer(fw_handle_t handle, u_int32_t *cycle_timer,
			  u_int64_t *local_time)
{
	int err;
	struct fw_cdev_get_cycle_timer ctr = { 0 };

	err = ioctl(handle->ioctl_fd, FW_CDEV_IOC_GET_CYCLE_TIMER, &ctr);
	if (!err) {
		*cycle_timer = ctr.cycle_timer;
		*local_time  = ctr.local_time;
	}
	return err;
}

int fw_read_cycle_timer_and_clock(fw_handle_t handle, u_int32_t *cycle_timer,
			  u_int64_t *local_time, clockid_t clk_id)
{
	int err;
	struct fw_cdev_get_cycle_timer2 ctr = {.clk_id = clk_id};

	err = ioctl(handle->ioctl_fd, FW_CDEV_IOC_GET_CYCLE_TIMER2, &ctr);
	if (!err) {
		*cycle_timer = ctr.cycle_timer;
		*local_time  = ctr.tv_sec * 1000000ULL +
			       ctr.tv_nsec / 1000;
	}
	return err;
}
