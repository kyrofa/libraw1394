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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"

/* old ISO API - kept for backwards compatibility */

static int do_iso_listen(struct raw1394_handle *handle, int channel)
{
        struct sync_cb_data sd = { 0, 0 };
        struct raw1394_reqhandle rh = { (req_callback_t)_raw1394_sync_cb, &sd };
        int err;
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);
        req->type = RAW1394_REQ_ISO_LISTEN;
        req->generation = handle->generation;
        req->misc = channel;
        req->tag = ptr2int(&rh);
        req->recvb = ptr2int(handle->buffer);
        req->length = HBUF_SIZE;

        err = write(handle->fd, req, sizeof(*req));
        while (!sd.done) {
                if (err < 0) return err;
                err = raw1394_loop_iterate(handle);
        }

        switch (sd.errcode) {
        case RAW1394_ERROR_ALREADY:
                errno = EALREADY;
                return -1;

        case RAW1394_ERROR_INVALID_ARG:
                errno = EINVAL;
                return -1;

        default:
                errno = 0;
                return sd.errcode;
        }
}

/**
 * raw1394_start_iso_rcv - enable isochronous receiving
 * @channel: channel number to start receiving on
 *
 * Enables the reception of isochronous packets in @channel on @handle.
 * Isochronous packets are then passed to the callback specified with
 * raw1394_set_iso_handler().
 **/
int raw1394_start_iso_rcv(struct raw1394_handle *handle, unsigned int channel)
{
        if (channel > 63) {
                errno = EINVAL;
                return -1;
        }

        return do_iso_listen(handle, channel);
}

/**
 * raw1394_stop_iso_rcv - stop isochronous receiving
 * @channel: channel to stop receiving on
 *
 * Stops the reception of isochronous packets in @channel on @handle.
 **/
int raw1394_stop_iso_rcv(struct raw1394_handle *handle, unsigned int channel)
{
        if (channel > 63) {
                errno = EINVAL;
                return -1;
        }

        return do_iso_listen(handle, ~channel);
}



/* new ISO API */


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
		       int xmit)
{
	size_t pgsize;

	/* already initialized? */
	if(handle->iso_buffer)
		return -1;
	
	handle->iso_status.config.buf_packets = buf_packets;
	handle->iso_status.config.max_packet_size = max_packet_size;
	handle->iso_status.config.channel = channel;
	handle->iso_status.config.speed = speed;
	handle->iso_status.config.irq_interval = irq_interval;
	
	if(ioctl(handle->fd, xmit ? RAW1394_ISO_XMIT_INIT : RAW1394_ISO_RECV_INIT, &handle->iso_status))
		return -1;

	handle->iso_buffer_bytes = handle->iso_status.config.buf_packets * handle->iso_status.buf_stride;

	/* make sure buffer is a multiple of the page size (for mmap) */
	pgsize = getpagesize();
	if(handle->iso_buffer_bytes % pgsize)
		handle->iso_buffer_bytes += pgsize - (handle->iso_buffer_bytes % pgsize);

	/* mmap the DMA buffer */
	handle->iso_buffer = mmap(NULL, handle->iso_buffer_bytes, PROT_READ | PROT_WRITE,
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
 * @max_packet_size: largest packet you need to handle, in bytes (not including the 8-byte isochronous header)
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
			  int channel,
			  enum raw1394_iso_speed speed,
			  int irq_interval)
{
	if(do_iso_init(handle, buf_packets, max_packet_size, channel, speed, irq_interval, 1))
		return -1;
	
	handle->iso_xmit_handler = handler;
	return 0;
}

/**
 * raw1394_iso_recv_init - initialize isochronous reception
 * @handler: handler function for receiving packets
 * @buf_packets: number of isochronous packets to buffer
 * @max_packet_size: largest packet you need to handle, in bytes (not including the 8-byte isochronous header)
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
			  int channel,
			  int irq_interval)
{
	/* any speed will work */
	if(do_iso_init(handle, buf_packets, max_packet_size, channel, RAW1394_ISO_SPEED_100, irq_interval, 0))
		return -1;

	handle->iso_recv_handler = handler;
	return 0;
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
	int retval = 0, packets_done = 0;
	
	if(!handle->iso_buffer)
		return -1;

	if(!handle->iso_xmit_handler)
		return -1;
	
	while(stat->n_packets > 0) {
		enum raw1394_iso_disposition disp;
		unsigned char *packet_data;
		struct raw1394_iso_packet_info *info;
		unsigned int len;
		unsigned char tag, sy;
		
		packet_data = handle->iso_buffer + stat->first_packet * stat->buf_stride
			                         + stat->packet_data_offset;
		
		info = (struct raw1394_iso_packet_info*) (handle->iso_buffer
							  + stat->first_packet * stat->buf_stride
							  + stat->packet_info_offset);
		
		/* call handler */
		disp = handle->iso_xmit_handler(handle,
						packet_data,
						&len, &tag, &sy,
						info->cycle,
						_raw1394_iso_dropped(handle));

		/* check if packet is too long */
		if(len > stat->config.max_packet_size) {
			retval = -1;
			break;
		}
	
		/* set packet metadata */
		info->len = len;
		info->tag = tag;
		info->sy = sy;
		
		/* advance packet cursors and cycle counter */
		stat->n_packets--;
		stat->first_packet = (stat->first_packet + 1) % stat->config.buf_packets;
		packets_done++;

		if(disp == RAW1394_ISO_DEFER) {
			break;
		} else if(disp == RAW1394_ISO_ERROR) {
			retval = -1;
			break;
		}
	}

	if(packets_done > 0) {
		if(ioctl(handle->fd, RAW1394_ISO_PRODUCE_CONSUME, packets_done))
			return -1;
	}
	
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
		munmap(handle->iso_buffer, handle->iso_buffer_bytes);
		ioctl(handle->fd, RAW1394_ISO_SHUTDOWN, 0);
		handle->iso_buffer = NULL;
	}
}

static int _raw1394_iso_recv_packets(raw1394handle_t handle)
{
	struct raw1394_iso_status *stat = &handle->iso_status;
	struct raw1394_iso_packet_info *info;

	int retval = 0, packets_done = 0;
	
	if(!handle->iso_buffer)
		return -1;

	if(!handle->iso_recv_handler)
		return -1;
	
	while(stat->n_packets > 0) {
		unsigned char *packet_data;
		struct raw1394_iso_packet_info *info;
		enum raw1394_iso_disposition disp;
		
		packet_data = handle->iso_buffer + stat->first_packet * stat->buf_stride
			                         + stat->packet_data_offset;

		info = (struct raw1394_iso_packet_info*) (handle->iso_buffer
							  + stat->first_packet * stat->buf_stride
							  + stat->packet_info_offset);

		/* call handler */
		disp = handle->iso_recv_handler(handle,
						packet_data,
						info->len, info->channel,
						info->tag, info->sy,
						info->cycle,
						_raw1394_iso_dropped(handle));

		/* advance packet cursors */
		stat->n_packets--;
		stat->first_packet = (stat->first_packet + 1) % stat->config.buf_packets;
		packets_done++;
		
		if(disp == RAW1394_ISO_DEFER) {
			break;
		} else if(disp == RAW1394_ISO_ERROR) {
			retval = -1;
			break;
		}
	}

	if(packets_done > 0) {
		if(ioctl(handle->fd, RAW1394_ISO_PRODUCE_CONSUME, packets_done))
			return -1;
	}
	
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

