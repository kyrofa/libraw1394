
#include <unistd.h>
#include <errno.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


int raw1394_start_read(struct raw1394_handle *handle, nodeid_t node,
                       nodeaddr_t addr, size_t length, quadlet_t *buffer,
                       unsigned long tag)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_ASYNC_READ;
        req->generation = handle->generation;
        req->tag = tag;

        req->address = ((u_int64_t)node << 48) | addr;
        req->length = length;
        req->recvb = buffer;

        return (int)write(handle->fd, req, sizeof(*req));
}

int raw1394_start_write(struct raw1394_handle *handle, nodeid_t node,
                        nodeaddr_t addr, size_t length, quadlet_t *data,
                        unsigned long tag)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_ASYNC_WRITE;
        req->generation = handle->generation;
        req->tag = tag;

        req->address = ((u_int64_t)node << 48) | addr;
        req->length = length;
        req->sendb = data;

        return (int)write(handle->fd, req, sizeof(*req));
}

int raw1394_start_lock(struct raw1394_handle *handle, nodeid_t node,
                       nodeaddr_t addr, unsigned int extcode, quadlet_t data,
                       quadlet_t arg, unsigned long tag)
{
        struct raw1394_request *req = &handle->req;
        quadlet_t sendbuf[2];

        if ((extcode > 7) || (extcode == 0)) {
                errno = EINVAL;
                return -1;
        }

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_LOCK;
        req->generation = handle->generation;
        req->tag = tag;

        req->address = ((u_int64_t)node << 48) | addr;
        req->sendb = sendbuf;

        switch (extcode) {
        case 3: /* EXTCODE_FETCH_ADD */
        case 4: /* EXTCODE_LITTLE_ADD */
                sendbuf[0] = data;
                req->length = 4;
                break;
        default:
                sendbuf[0] = arg;
                sendbuf[1] = data;
                req->length = 8;
                break;
        }

        return (int)write(handle->fd, req, sizeof(*req));
}


#define SYNCFUNC_VARS                                                     \
        struct sync_cb_data sd = { 0, 0 };                                \
        struct raw1394_reqhandle rh = { (req_callback_t)_raw1394_sync_cb, \
                                        &sd };                            \
        int err

#define SYNCFUNC_BODY                               \
        while (!sd.done) {                          \
                if (err < 0) return err;            \
                err = raw1394_loop_iterate(handle); \
        }                                           \
        return sd.errcode

int raw1394_read(struct raw1394_handle *handle, nodeid_t node, nodeaddr_t addr,
                 size_t length, quadlet_t *buffer)
{
        SYNCFUNC_VARS;

        err = raw1394_start_read(handle, node, addr, length, buffer, 
                                 (unsigned long)&rh);

        SYNCFUNC_BODY;
}

int raw1394_write(struct raw1394_handle *handle, nodeid_t node, nodeaddr_t addr,
                  size_t length, quadlet_t *data)
{
        SYNCFUNC_VARS;

        err = raw1394_start_write(handle, node, addr, length, data, 
                                  (unsigned long)&rh);

        SYNCFUNC_BODY;
}

int raw1394_lock(struct raw1394_handle *handle, nodeid_t node, nodeaddr_t addr,
                 unsigned int extcode, quadlet_t data, quadlet_t arg)
{
        SYNCFUNC_VARS;

        err = raw1394_start_lock(handle, node, addr, extcode, data, arg,
                                 (unsigned long)&rh);

        SYNCFUNC_BODY;
}

#undef SYNCFUNC_VARS
#undef SYNCFUNC_BODY
