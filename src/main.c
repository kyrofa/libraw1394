
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


static int bus_reset_default(struct raw1394_handle *handle)
{
        return 0;
}

static int tag_handler_default(struct raw1394_handle *handle, unsigned long tag,
                               int error)
{
        struct raw1394_reqhandle *rh;

        if (tag) {
                rh = (struct raw1394_reqhandle *)tag;
                return rh->callback(handle, rh->data, error);
        } else {
                return -1;
        }
}

int _raw1394_sync_cb(struct raw1394_handle *unused, struct sync_cb_data *data,
                     int error)
{
        data->errcode = error;
        data->done = 1;
        return 0;
}




static unsigned int init_rawdevice(struct raw1394_handle *h)
{
        struct raw1394_request *req = &h->req;

        CLEAR_REQ(req);
        req->type = RAW1394_REQ_INITIALIZE;
        req->misc = RAW1394_KERNELAPI_VERSION;

        if (write(h->fd, req, sizeof(*req)) < 0) return -1;
        if (read(h->fd, req, sizeof(*req)) < 0) return -1;
        if (req->error) {
                errno = 0;
                return -1;
        }

        return req->generation;
}


struct raw1394_handle *raw1394_get_handle(void)
{
        struct raw1394_handle *handle;

        handle = malloc(sizeof(struct raw1394_handle));
        if (!handle) {
                errno = ENOMEM;
                return NULL;
        }

        handle->fd = open("/dev/raw1394", O_RDWR);
        if (handle->fd < 0) {
                free(handle);
                return NULL;
        }

        handle->generation = init_rawdevice(handle);
        if (handle->generation < 0) {
                close(handle->fd);
                free(handle);
                return NULL;
        }

        handle->bus_reset_handler = bus_reset_default;
        handle->tag_handler = tag_handler_default;
        memset(handle->iso_handler, 0, sizeof(handle->iso_handler));
        return handle;
}

void raw1394_destroy_handle(struct raw1394_handle *handle)
{
        if (handle) {
                close(handle->fd);
                free(handle);
        }
}

int raw1394_get_fd(struct raw1394_handle *handle)
{
        return handle->fd;
}

unsigned int raw1394_get_generation(struct raw1394_handle *handle)
{
        return handle->generation;
}

int raw1394_get_nodecount(struct raw1394_handle *handle)
{
        return handle->num_of_nodes;
}

nodeid_t raw1394_get_local_id(struct raw1394_handle *handle)
{
        return handle->local_id;
}


int raw1394_get_port_info(struct raw1394_handle *handle, 
                          struct raw1394_portinfo *pinf, int maxports)
{
        int num;
        struct raw1394_request *req = &handle->req;
        struct raw1394_khost_list *khl;

        CLEAR_REQ(req);
        req->type = RAW1394_REQ_LIST_CARDS;
        req->generation = handle->generation;
        req->recvb = handle->buffer;
        req->length = HBUF_SIZE;

        while (1) {
                if (write(handle->fd, req, sizeof(*req)) < 0) return -1;
                if (read(handle->fd, req, sizeof(*req)) < 0) return -1;

                if (!req->error) break;

                if (req->error == RAW1394_ERROR_GENERATION) {
                        handle->generation = req->generation;
                        continue;
                }

                return -1;
        }

        for (num = req->misc, khl = (struct raw1394_khost_list *)handle->buffer;
             num && maxports; num--, maxports--, pinf++, khl++) {
                pinf->nodes = khl->nodes;
                strcpy(pinf->name, khl->name);
        }

        return req->misc;
}

int raw1394_set_port(struct raw1394_handle *handle, int port)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_SET_CARD;
        req->generation = handle->generation;
        req->misc = port;

        if (write(handle->fd, req, sizeof(*req)) < 0) return -1;
        if (read(handle->fd, req, sizeof(*req)) < 0) return -1;

        switch (req->error) {
        case RAW1394_ERROR_GENERATION:
                handle->generation = req->generation;
                errno = ESTALE;
                return -1;
        case RAW1394_ERROR_INVALID_ARG:
                errno = EINVAL;
                return -1;
        case RAW1394_ERROR_NONE:
                handle->num_of_nodes = req->misc & 0xffff;
                handle->local_id = req->misc >> 16;
                return 0;
        default:
                errno = 0;
                return -1;
        }
}
