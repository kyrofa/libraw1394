/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000,2001,2002 Andreas Bombe
 *                     2002 Manfred Weihs <weihs@ict.tuwien.ac.at>
 *                     2002 Christian Toegel <christian.toegel@gmx.at>
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 *
 *
 * Contributions:
 *
 * Manfred Weihs <weihs@ict.tuwien.ac.at>
 *        address range mapping
 * Christian Toegel <christian.toegel@gmx.at>
 *        address range mapping
 */

#include <config.h>
#include <unistd.h>
#include <byteswap.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


/**
 * raw1394_loop_iterate - get and process one event message
 *
 * Get one new message through handle and process it with the registered message
 * handler.  This function will return %-1 for an error or the return value of
 * the handler which got executed.  The default handlers always return zero.
 *
 * Note that some other library functions may call this function multiple times
 * to wait for their completion, some handler return values may get lost if you
 * use these.
 **/
int raw1394_loop_iterate(struct raw1394_handle *handle)
{
        struct raw1394_request *req = &handle->req;
        int retval = 0, channel;

        if (read(handle->fd, req, sizeof(*req)) < 0) {
                return -1;
        }

        switch (req->type) {
        case RAW1394_REQ_BUS_RESET:
                if (handle->protocol_version == 3) {
                        handle->num_of_nodes = req->misc & 0xffff;
                        handle->local_id = req->misc >> 16;
                } else {
                        handle->num_of_nodes = req->misc & 0xff;
                        handle->irm_id = ((req->misc >> 8) & 0xff) | 0xffc0;
                        handle->local_id = req->misc >> 16;
                }

                if (handle->bus_reset_handler) {
                        retval = handle->bus_reset_handler(handle,
                                                           req->generation);
                }
                break;

        case RAW1394_REQ_ISO_RECEIVE:
		/* obsolete API, not used anymore */
		break;

        case RAW1394_REQ_FCP_REQUEST:
                if (handle->fcp_handler) {
                        retval = handle->fcp_handler(handle, req->misc & 0xffff,
                                                     req->misc >> 16,
                                                     req->length,
                                                     (char *)handle->buffer);
                }
                break;

        case RAW1394_REQ_ARM:
                if (handle->arm_tag_handler) {
                        retval = handle->arm_tag_handler(handle, req->tag,
                                 (req->misc & (0xFF)), 
                                 ((req->misc >> 16) & (0xFFFF)),
                                 int2ptr(req->recvb));
                } 
                break;
                
        case RAW1394_REQ_ECHO:
                retval=req->misc;
                break;

        case RAW1394_REQ_RAWISO_ACTIVITY:
                retval = _raw1394_iso_iterate(handle);
                break;
        
        default:
                if (handle->tag_handler) {
                        retval = handle->tag_handler(handle, req->tag,
                                                     req->error);
                }
                break;
        }

        return retval;
}


/**
 * raw1394_set_bus_reset_handler - set bus reset handler
 * @new_h: pointer to new handler
 *
 * Sets the handler to be called on every bus reset to @new_h and returns the
 * old handler. The default handler just calls raw1394_update_generation().
 **/
bus_reset_handler_t raw1394_set_bus_reset_handler(struct raw1394_handle *handle,
                                                  bus_reset_handler_t new)
{
        bus_reset_handler_t old;

        old = handle->bus_reset_handler;
        handle->bus_reset_handler = new;

        return old;
}

/**
 * raw1394_set_tag_handler - set request completion handler
 * @new_h: pointer to new handler
 *
 * Sets the handler to be called whenever a request completes to @new_h and
 * returns the old handler.  The default handler interprets the tag as a pointer
 * to a &struct raw1394_reqhandle and calls the callback in there.
 *
 * Care must be taken when replacing the tag handler and calling the synchronous
 * versions of the transaction functions (i.e. raw1394_read(), raw1394_write(),
 * raw1394_lock(), raw1394_iso_write()) since these do pass pointers to &struct
 * raw1394_reqhandle as the tag and expect the callback to be invoked.
 **/
tag_handler_t raw1394_set_tag_handler(struct raw1394_handle *handle, 
                                      tag_handler_t new)
{
        tag_handler_t old;

        old = handle->tag_handler;
        handle->tag_handler = new;

        return old;
}

arm_tag_handler_t raw1394_set_arm_tag_handler(struct raw1394_handle *handle, 
                                      arm_tag_handler_t new)
{
        arm_tag_handler_t old;

        old = handle->arm_tag_handler;
        handle->arm_tag_handler = new;

        return old;
}

/**
 * raw1394_set_fcp_handler - set FCP handler
 * @new_h: pointer to new handler
 *
 * Sets the handler to be called when either FCP command or FCP response
 * registers get written to @new_h and returns the old handler.  The default
 * handler does nothing.
 *
 * In order to actually get FCP events, you have to enable it with
 * raw1394_start_fcp_listen() and can stop it with raw1394_stop_fcp_listen().
 **/
fcp_handler_t raw1394_set_fcp_handler(struct raw1394_handle *handle,
                                      fcp_handler_t new)
{
        fcp_handler_t old;

        old = handle->fcp_handler;
        handle->fcp_handler = new;

        return old;
}
