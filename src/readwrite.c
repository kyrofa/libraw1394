/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000,2001,2002 Andreas Bombe
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 */

#include <config.h>
#include <unistd.h>
#include <errno.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


/**
 * raw1394_start_read - initiate a read transaction
 * @node: target node
 * @addr: address to read from
 * @length: amount of data to read
 * @buffer: pointer to buffer where data will be saved
 * @tag: data to identify the request to completion handler
 *
 * This function starts the specified read request and returns %0 for success
 * and a negative number for an error, in which case errno will be set.  If
 * @length is %4 a quadlet read is initiated and a block read otherwise.
 *
 * The transaction is only started, no success of the transaction is implied
 * with a successful return of this function.  When the transaction completes, a
 * raw1394_loop_iterate() will call the tag handler and pass it the tag and
 * error code of the transaction.  @tag should therefore be set to something
 * that uniquely identifies this transaction (e.g. a struct pointer casted to
 * unsigned long).
 **/
int raw1394_start_read(struct raw1394_handle *handle, nodeid_t node,
                       nodeaddr_t addr, size_t length, quadlet_t *buffer,
                       unsigned long tag)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_ASYNC_READ;
        req->generation = handle->generation;
        req->tag = tag;

        req->address = ((__u64)node << 48) | addr;
        req->length = length;
        req->recvb = ptr2int(buffer);

        return (int)write(handle->fd, req, sizeof(*req));
}


/**
 * raw1394_start_write - initiate a write transaction
 * @node: target node
 * @addr: address to write to
 * @length: amount of data to write
 * @data: pointer to data to be sent
 * @tag: data to identify the request to completion handler
 *
 * This function starts the specified write request and returns %0 for success
 * and a negative number for an error, in which case errno will be set.  If
 * @length is %4 a quadlet write is initiated and a block write otherwise.
 *
 * The transaction is only started, no success of the transaction is implied
 * with a successful return of this function.  When the transaction completes, a
 * raw1394_loop_iterate() will call the tag handler and pass it the tag and
 * error code of the transaction.  @tag should therefore be set to something
 * that uniquely identifies this transaction (e.g. a struct pointer casted to
 * unsigned long).
 **/
int raw1394_start_write(struct raw1394_handle *handle, nodeid_t node,
                        nodeaddr_t addr, size_t length, quadlet_t *data,
                        unsigned long tag)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_ASYNC_WRITE;
        req->generation = handle->generation;
        req->tag = tag;

        req->address = ((__u64)node << 48) | addr;
        req->length = length;
        req->sendb = ptr2int(data);

        return (int)write(handle->fd, req, sizeof(*req));
}


/**
 * raw1394_start_read - initiate a lock transaction
 * @node: target node
 * @addr: address to read from
 * @extcode: extended transaction code determining the lock operation
 * @data: data part of lock parameters
 * @arg: arg part of lock parameters
 * @result: address where return value will be written
 * @tag: data to identify the request to completion handler
 *
 * This function starts the specified lock request and returns %0 for success
 * and a negative number for an error, in which case errno will be set.
 *
 * The transaction is only started, no success of the transaction is implied
 * with a successful return of this function.  When the transaction completes, a
 * raw1394_loop_iterate() will call the tag handler and pass it the tag and
 * error code of the transaction.  @tag should therefore be set to something
 * that uniquely identifies this transaction (e.g. a struct pointer casted to
 * unsigned long).
 **/
int raw1394_start_lock(struct raw1394_handle *handle, nodeid_t node,
                       nodeaddr_t addr, unsigned int extcode, quadlet_t data,
                       quadlet_t arg, quadlet_t *result, unsigned long tag)
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

        req->address = ((__u64)node << 48) | addr;
        req->sendb = ptr2int(sendbuf);
        req->recvb = ptr2int(result);
        req->misc = extcode;

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


/**
 * raw1394_start_iso_write - initiate an isochronous packet write
 * @channel: channel number on which to send on
 * @tag: data to be put into packet's tag field
 * @sy: data to be put into packet's sy field
 * @speed: speed at which to send
 * @length: amount of data to send
 * @data: pointer to data to send
 * @rawtag: data to identify the request to completion handler
 *
 * This function starts the specified isochronous packet transmission and
 * returns %0 for success and a negative number for an error, in which case
 * errno will be set.
 *
 * When the send completes, a raw1394_loop_iterate() will call the tag handler
 * and pass it the tag and error code of the transaction.  @tag should therefore
 * be set to something that uniquely identifies this transaction (e.g. a struct
 * pointer casted to unsigned long).
 *
 * Isochronous packets are automatically
 **/
int raw1394_start_iso_write(struct raw1394_handle *handle, unsigned int channel,
                            unsigned int tag, unsigned int sy,
                            unsigned int speed, size_t length, quadlet_t *data,
                            unsigned long rawtag)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_ISO_SEND;
        req->generation = handle->generation;
        req->tag = rawtag;

        req->address = ((__u64)channel << 48) | speed;
        req->misc = (tag << 16) | sy;
        req->length = length;
        req->sendb = ptr2int(data);

        return (int)write(handle->fd, req, sizeof(*req));
}


#define SYNCFUNC_VARS                                                     \
        struct sync_cb_data sd = { 0, 0 };                                \
        struct raw1394_reqhandle rh = { (req_callback_t)_raw1394_sync_cb, \
                                        &sd };                            \
        int err = 0

#define SYNCFUNC_BODY                                 \
        while (!sd.done) {                            \
                if (err < 0) return err;              \
                err = raw1394_loop_iterate(handle);   \
        }                                             \
        handle->err = sd.errcode;                     \
        errno = raw1394_errcode_to_errno(sd.errcode); \
        return (errno ? -1 : 0)

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
                 unsigned int extcode, quadlet_t data, quadlet_t arg,
                 quadlet_t *result)
{
        SYNCFUNC_VARS;

        err = raw1394_start_lock(handle, node, addr, extcode, data, arg, result,
                                 (unsigned long)&rh);

        SYNCFUNC_BODY;
}

int raw1394_iso_write(struct raw1394_handle *handle, unsigned int channel,
                      unsigned int tag, unsigned int sy, unsigned int speed,
                      size_t length, quadlet_t *data)
{
        SYNCFUNC_VARS;

        err = raw1394_start_iso_write(handle, channel, tag, sy, speed, length,
                                      data, (unsigned long)&rh);

        SYNCFUNC_BODY;
}

#undef SYNCFUNC_VARS
#undef SYNCFUNC_BODY
