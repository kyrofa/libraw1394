
#include <unistd.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


int raw1394_loop_iterate(struct raw1394_handle *handle)
{
        struct raw1394_request *req = &handle->req;
        int retval = 0;

        if (read(handle->fd, req, sizeof(*req)) < 0) {
                return -1;
        }

        switch (req->type) {
        case RAW1394_REQ_BUS_RESET:
                handle->generation = req->generation;
                handle->num_of_nodes = req->misc & 0xffff;
                handle->local_id = req->misc >> 16;

                if (handle->bus_reset_handler) {
                        retval = handle->bus_reset_handler(handle);
                }
                break;

        case RAW1394_REQ_ISO_RECEIVE:
                if (handle->iso_handler) {
                        retval = handle->iso_handler(handle,
                                                     (handle->buffer[0] >> 8)
                                                     & 0x3f, req->length,
                                                     handle->buffer);
                }
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


bus_reset_handler_t raw1394_set_bus_reset_handler(struct raw1394_handle *handle,
                                                  bus_reset_handler_t new)
{
        bus_reset_handler_t old;

        old = handle->bus_reset_handler;
        handle->bus_reset_handler = new;

        return old;
}

tag_handler_t raw1394_set_tag_handler(struct raw1394_handle *handle, 
                                      tag_handler_t new)
{
        tag_handler_t old;

        old = handle->tag_handler;
        handle->tag_handler = new;

        return old;
}

iso_handler_t raw1394_set_iso_handler(struct raw1394_handle *handle,
                                      iso_handler_t new)
{
        iso_handler_t old;

        old = handle->iso_handler;
        handle->iso_handler = new;

        return old;
}
