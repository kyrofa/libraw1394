/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000 Andreas Bombe
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 */

#include <config.h>
#include <errno.h>
#include <unistd.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


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

int raw1394_start_iso_rcv(struct raw1394_handle *handle, unsigned int channel)
{
        if (channel > 63) {
                errno = EINVAL;
                return -1;
        }

        return do_iso_listen(handle, channel);
}

int raw1394_stop_iso_rcv(struct raw1394_handle *handle, unsigned int channel)
{
        if (channel > 63) {
                errno = EINVAL;
                return -1;
        }

        return do_iso_listen(handle, ~channel);
}
