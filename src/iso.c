
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
        req->tag = (unsigned long)&rh;
        req->recvb = handle->buffer;
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
