/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000,2001,2002 Andreas Bombe
 *        new ISO API by Dan Maas
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 */

#include <config.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <byteswap.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"

/* reset the dropped counter each time it is seen */
static unsigned int _raw1394_iso_dropped(raw1394handle_t handle)
{
	unsigned int retval = handle->iso_packets_dropped;
	handle->iso_packets_dropped = 0;
	return retval;
}

/* common code for iso_xmit_init and iso_recv_init */
static int do_iso_init(raw1394handle_t handle,
		       unsigned int buf_packets,
		       unsigned int max_packet_size,
		       int channel,
		       enum raw1394_iso_speed speed,
		       int irq_interval,
		       int cmd)
{
	unsigned int bufsize, stride;

	/* already initialized? */
	if(handle->iso_buffer)
		return -1;

	/* choose a power-of-two stride for the packet data buffer,
	   so that an even number of packets fits on one page */
	for(stride = 4; stride < max_packet_size; stride *= 2);

	if(stride > getpagesize()) {
		errno = ENOMEM;
		return -1;
	}

	handle->iso_buf_stride = stride;

	handle->iso_status.config.data_buf_size = stride * buf_packets;
	handle->iso_status.config.buf_packets = buf_packets;
	handle->iso_status.config.channel = channel;
	handle->iso_status.config.speed = speed;
	handle->iso_status.config.irq_interval = irq_interval;

	if(ioctl(handle->fd, cmd, &handle->iso_status))
		return -1;

	/* mmap the DMA buffer */
	/* (we assume the kernel sets buf_size to an even number of pages) */
	handle->iso_buffer = mmap(NULL,
				  handle->iso_status.config.data_buf_size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, handle->fd, 0);

	if(handle->iso_buffer == (unsigned char*) MAP_FAILED) {
		handle->iso_buffer = NULL;
		ioctl(handle->fd, RAW1394_ISO_SHUTDOWN, 0);
		return -1;
	}

	handle->iso_status.overflows = 0;
	handle->iso_packets_dropped = 0;

	handle->iso_xmit_handler = NULL;
	handle->iso_recv_handler = NULL;

	return 0;			
}

/**
 * raw1394_iso_xmit_init - initialize isochronous transmission
 * @handler: handler function for queueing packets
 * @buf_packets: number of isochronous packets to buffer
 * @max_packet_size: largest packet you need to handle, in bytes (not including the isochronous header)
 * @channel: isochronous channel on which to transmit
 * @speed: speed at which to transmit
 * @irq_interval: maximum latency of wake-ups, in packets (-1 if you don't care)
 *
 * Allocates all user and kernel resources necessary for isochronous transmission.
 **/
int raw1394_iso_xmit_init(raw1394handle_t handle,
			  raw1394_iso_xmit_handler_t handler,
			  unsigned int buf_packets,
			  unsigned int max_packet_size,
			  unsigned char channel,
			  enum raw1394_iso_speed speed,
			  int irq_interval)
{
	if(do_iso_init(handle, buf_packets, max_packet_size, channel, speed,
		       irq_interval, RAW1394_ISO_XMIT_INIT))
		return -1;

	handle->iso_xmit_handler = handler;
	handle->next_packet = 0;

	return 0;
}

/**
 * raw1394_iso_recv_init - initialize isochronous reception
 * @handler: handler function for receiving packets
 * @buf_packets: number of isochronous packets to buffer
 * @max_packet_size: largest packet you need to handle, in bytes (not including the isochronous header)
 * @channel: isochronous channel to receive
 * @speed: speed at which to receive
 * @irq_interval: maximum latency of wake-ups, in packets (-1 if you don't care)
 *
 * Allocates all user and kernel resources necessary for isochronous reception.
 **/
int raw1394_iso_recv_init(raw1394handle_t handle,
			  raw1394_iso_recv_handler_t handler,
			  unsigned int buf_packets,
			  unsigned int max_packet_size,
			  unsigned char channel,
			  int irq_interval)
{
	/* any speed will work */
	if(do_iso_init(handle, buf_packets, max_packet_size, channel, RAW1394_ISO_SPEED_100,
		       irq_interval, RAW1394_ISO_RECV_INIT))
		return -1;

	handle->iso_recv_handler = handler;
	return 0;
}

/**
 * raw1394_iso_multichannel_recv_init - initialize multi-channel isochronous reception
 * @handler: handler function for receiving packets
 * @buf_packets: number of isochronous packets to buffer
 * @max_packet_size: largest packet you need to handle, in bytes (not including the isochronous header)
 * @speed: speed at which to receive
 * @irq_interval: maximum latency of wake-ups, in packets (-1 if you don't care)
 *
 * Allocates all user and kernel resources necessary for isochronous reception.
 **/
int raw1394_iso_multichannel_recv_init(raw1394handle_t handle,
				       raw1394_iso_recv_handler_t handler,
				       unsigned int buf_packets,
				       unsigned int max_packet_size,
				       int irq_interval)
{
	/* any speed will work */
	if(do_iso_init(handle, buf_packets, max_packet_size, -1, RAW1394_ISO_SPEED_100,
		       irq_interval, RAW1394_ISO_RECV_INIT))
		return -1;

	handle->iso_recv_handler = handler;
	return 0;
}

/**
 * raw1394_iso_recv_listen_channel - listen to a specific channel in multi-channel mode
 **/
int raw1394_iso_recv_listen_channel(raw1394handle_t handle, unsigned char channel)
{
	if(!handle->iso_buffer)
		return -1;
	if(!handle->iso_recv_handler)
		return -1;

	return ioctl(handle->fd, RAW1394_ISO_RECV_LISTEN_CHANNEL, channel);
}

/**
 * raw1394_iso_recv_unlisten_channel - stop listening  to a specific channel in multi-channel mode
 **/
int raw1394_iso_recv_unlisten_channel(raw1394handle_t handle, unsigned char channel)
{
	if(!handle->iso_buffer)
		return -1;
	if(!handle->iso_recv_handler)
		return -1;

	return ioctl(handle->fd, RAW1394_ISO_RECV_UNLISTEN_CHANNEL, channel);
}

/**
 * raw1394_iso_recv_set_channel_mask - listen or unlisten to a whole bunch of channels at once
 * @mask: 64-bit mask of channels, 1 means listen, 0 means unlisten,
 *        channel 0 is LSB, channel 63 is MSB
 *
 * for multi-channel reception mode only
 **/
int raw1394_iso_recv_set_channel_mask(raw1394handle_t handle, u_int64_t mask)
{
	if(!handle->iso_buffer)
		return -1;
	if(!handle->iso_recv_handler)
		return -1;

	return ioctl(handle->fd, RAW1394_ISO_RECV_SET_CHANNEL_MASK, (void*) &mask);
}

/**
 * raw1394_iso_recv_start - begin isochronous reception
 * @start_on_cycle: isochronous cycle number on which to start (-1 if you don't care)
 **/
int raw1394_iso_recv_start(raw1394handle_t handle, int start_on_cycle)
{
	if(!handle->iso_buffer)
		return -1;
	if(!handle->iso_recv_handler)
		return -1;

	if(ioctl(handle->fd, RAW1394_ISO_RECV_START, start_on_cycle))
		return -1;

	return 0;
}


static int _raw1394_iso_xmit_queue_packets(raw1394handle_t handle)
{
	struct raw1394_iso_status *stat = &handle->iso_status;
	struct raw1394_iso_packets packets;
	int retval = -1;

	if(!handle->iso_buffer)
		goto out;

	if(!handle->iso_xmit_handler)
		goto out;

	/* we could potentially send up to stat->n_packets packets */
	packets.n_packets = 0;
	packets.infos = malloc(stat->n_packets * sizeof(struct raw1394_iso_packet_info));
	if(packets.infos == NULL)
		goto out;

	while(stat->n_packets > 0) {
		enum raw1394_iso_disposition disp;
		unsigned int len;
		
		struct raw1394_iso_packet_info *info = &packets.infos[packets.n_packets];

		info->offset = handle->iso_buf_stride * handle->next_packet;
		
		/* call handler */
		disp = handle->iso_xmit_handler(handle,
						handle->iso_buffer + info->offset,
						&len,
						&info->tag, &info->sy,
						stat->xmit_cycle,
						_raw1394_iso_dropped(handle));
		info->len = len;
		
		/* advance packet cursors and cycle counter */
		stat->n_packets--;
		handle->next_packet = (handle->next_packet + 1) % stat->config.buf_packets;
		if(stat->xmit_cycle != -1)
			stat->xmit_cycle = (stat->xmit_cycle + 1) % 8000;
		packets.n_packets++;

		if(disp == RAW1394_ISO_DEFER) {
			/* queue an event so that we don't hang in the next read() */
			if(ioctl(handle->fd, RAW1394_ISO_QUEUE_ACTIVITY, 0))
				goto out_produce;
			break;
		} else if(disp == RAW1394_ISO_ERROR) {
			goto out_produce;
		}
	}

	/* success */
	retval = 0;

out_produce:
	if(packets.n_packets > 0) {
		if(ioctl(handle->fd, RAW1394_ISO_XMIT_PACKETS, &packets))
			retval = -1;
	}
out_free:
	free(packets.infos);
out:	
	return retval;
}


/**
 * raw1394_iso_xmit_start - begin isochronous transmission
 * @start_on_cycle: isochronous cycle number on which to start (-1 if you don't care)
 * @prebuffer_packets: number of packets to queue up before starting transmission (-1 if you don't care)
 **/
int raw1394_iso_xmit_start(raw1394handle_t handle, int start_on_cycle, int prebuffer_packets)
{
	int args[2];

	if(!handle->iso_buffer)
		return -1;
	if(!handle->iso_xmit_handler)
		return -1;

	args[0] = start_on_cycle;
	args[1] = prebuffer_packets;

	if(ioctl(handle->fd, RAW1394_ISO_XMIT_START, &args[0]))
		return -1;

	return 0;
}

/**
 * raw1394_iso_stop - halt isochronous transmission or reception
 **/
void raw1394_iso_stop(raw1394handle_t handle)
{
	if(!handle->iso_buffer)
		return;

	ioctl(handle->fd, RAW1394_ISO_STOP, 0);
}

/**
 * raw1394_iso_shutdown - clean up and deallocate all resources for isochronous transmission or reception
 **/
void raw1394_iso_shutdown(raw1394handle_t handle)
{
	if(handle->iso_buffer) {
		raw1394_iso_stop(handle);
		munmap(handle->iso_buffer, handle->iso_status.config.data_buf_size);
		ioctl(handle->fd, RAW1394_ISO_SHUTDOWN, 0);
		handle->iso_buffer = NULL;
	}
}

static int _raw1394_iso_recv_packets(raw1394handle_t handle)
{
	struct raw1394_iso_status *stat = &handle->iso_status;
	struct raw1394_iso_packets packets;

	int retval = -1, packets_done = 0;

	if(!handle->iso_buffer)
		goto out;

	if(!handle->iso_recv_handler)
		goto out;

	/* ask the kernel to fill an array with packet info structs */
	packets.n_packets = stat->n_packets;
	packets.infos = malloc(packets.n_packets * sizeof(struct raw1394_iso_packet_info));
	if(packets.infos == NULL)
		goto out;

	if(ioctl(handle->fd, RAW1394_ISO_RECV_PACKETS, &packets) < 0)
		goto out_free;

	while(stat->n_packets > 0) {
		struct raw1394_iso_packet_info *info;
		enum raw1394_iso_disposition disp;

		info = &packets.infos[packets_done];

		/* call handler */
		disp = handle->iso_recv_handler(handle,
						handle->iso_buffer + info->offset,
						info->len, info->channel,
						info->tag, info->sy,
						info->cycle,
						_raw1394_iso_dropped(handle));

		/* advance packet cursors */
		stat->n_packets--;
		packets_done++;
		
		if(disp == RAW1394_ISO_DEFER) {
			/* queue an event so that we don't hang in the next read() */
			if(ioctl(handle->fd, RAW1394_ISO_QUEUE_ACTIVITY, 0))
				goto out_consume;
			break;
		} else if(disp == RAW1394_ISO_ERROR) {
			goto out_consume;
		}
	}

	/* success */
	retval = 0;

out_consume:
	if(packets_done > 0) {
		if(ioctl(handle->fd, RAW1394_ISO_RECV_RELEASE_PACKETS, packets_done))
			retval = -1;
	}
out_free:
	free(packets.infos);
out:	
	return retval;
}

/* run the ISO state machine; called from raw1394_loop_iterate()  */
int _raw1394_iso_iterate(raw1394handle_t handle)
{
	int err;

	if(!handle->iso_buffer)
		return 0;

	err = ioctl(handle->fd, RAW1394_ISO_GET_STATUS, &handle->iso_status);
	if(err != 0)
		return err;

	handle->iso_packets_dropped += handle->iso_status.overflows;

	if(handle->iso_xmit_handler) {
		return _raw1394_iso_xmit_queue_packets(handle);
	} else if(handle->iso_recv_handler) {
		return _raw1394_iso_recv_packets(handle);
	}

	return 0;
}

