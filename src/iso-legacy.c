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
#include <byteswap.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"

/* legacy ISO API - emulated for backwards compatibility
 *
 * (this code emulates the behavior of the old API using
 * the new "rawiso" API)
 */

static enum raw1394_iso_disposition legacy_iso_handler(raw1394handle_t handle,
						       unsigned char *data,
						       unsigned int len,
						       unsigned char channel,
						       unsigned char tag,
						       unsigned char sy,
						       unsigned int cycle,
						       unsigned int dropped);

/**
 * raw1394_set_iso_handler - set isochronous packet handler
 * @new_h: pointer to new handler
 *
 * Sets the handler to be called when an isochronous packet is received to
 * @new_h and returns the old handler.  The default handler does nothing.
 *
 * In order to actually get iso packet events, receiving on a specific channel
 * first has to be enabled with raw1394_start_iso_rcv() and can be stopped again
 * with raw1394_stop_iso_rcv().
 **/
iso_handler_t raw1394_set_iso_handler(struct raw1394_handle *handle,
                                      unsigned int channel, iso_handler_t new)
{
        if (channel >= 64)
		goto err;

	/* is this channel already being used? */
	if (handle->iso_handler[channel] != NULL)
		goto err;
	  
	/* start up the recv context, if necessary */
	if (!handle->legacy_iso_active) {
		/* hmm, is there a good average value for max_packet_size? */
		if (raw1394_iso_multichannel_recv_init(handle,
						      legacy_iso_handler,
						      1024,
						      500,
						      -1))
			goto err;

		if (raw1394_iso_recv_start(handle, -1)) {
			raw1394_iso_shutdown(handle);
			goto err;
		}

		handle->legacy_iso_active = 1;
	}
	
        if (new == NULL) {
                iso_handler_t old = handle->iso_handler[channel];
                handle->iso_handler[channel] = NULL;
                return old;
        } else {
		handle->iso_handler[channel] = new;
		return NULL;
	}

err:
	return (iso_handler_t)-1;
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
	if (!handle->legacy_iso_active || channel > 63) {
                errno = EINVAL;
                return -1;
        }

	return raw1394_iso_recv_listen_channel(handle, channel);
}

/**
 * raw1394_stop_iso_rcv - stop isochronous receiving
 * @channel: channel to stop receiving on
 *
 * Stops the reception of isochronous packets in @channel on @handle.
 **/
int raw1394_stop_iso_rcv(struct raw1394_handle *handle, unsigned int channel)
{
	if (!handle->legacy_iso_active || channel > 63) {
                errno = EINVAL;
                return -1;
        }

	return raw1394_iso_recv_unlisten_channel(handle, channel);
}

static enum raw1394_iso_disposition legacy_iso_handler(raw1394handle_t handle,
						       unsigned char *data,
						       unsigned int len,
						       unsigned char channel,
						       unsigned char tag,
						       unsigned char sy,
						       unsigned int cycle,
						       unsigned int dropped)
{
	size_t length;
	quadlet_t *buf;

	if (!handle->iso_handler[channel])
		return RAW1394_ISO_OK;

	length = len;
	buf = (quadlet_t*) data;

	/* back up one quadlet to get the ISO header */
	/* (note: we assume the card is keeping ISO headers!) */
	buf -= 1;
	length += 4;

	/* pad length to quadlet boundary */
	if (length % 4)
		length += 4 - (length%4);

	/* make the ISO header big-endian, regardless of host byte order */
#ifndef WORDS_BIGENDIAN
	buf[0] = bswap_32(buf[0]);
#endif

	if (handle->iso_handler[channel](handle, channel, length, buf))
		return RAW1394_ISO_ERROR;

	return RAW1394_ISO_OK;
}
