/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000,2001,2002 Andreas Bombe
 *               2001, 2002 Manfred Weihs <weihs@ict.tuwien.ac.at>
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
 *        configuration ROM manipulation
 *        address range mapping
 * Christian Toegel <christian.toegel@gmx.at>
 *        address range mapping
 *        reset notification control (switch on/off)
 *        reset with selection of type (short/long)
 */

#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"


static int bus_reset_default(struct raw1394_handle *handle, unsigned int gen)
{
        raw1394_update_generation(handle, gen);
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

static int arm_tag_handler_default(struct raw1394_handle *handle, unsigned long tag,
                               byte_t request_type, unsigned int requested_length,
			       void *data)
{
        struct raw1394_arm_reqhandle *rh;
        struct arm_request_response *arm_req_resp;

        if (tag) {
                rh = (struct raw1394_arm_reqhandle *)tag;
                arm_req_resp  = (struct arm_request_response *) data;
                return rh->arm_callback(handle, arm_req_resp, 
                                        requested_length, rh->pcontext, 
                                        request_type);
        } else {
                /* error ... */
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
        h->protocol_version = RAW1394_KERNELAPI_VERSION;

        if (write(h->fd, req, sizeof(*req)) < 0) return -1;
        if (read(h->fd, req, sizeof(*req)) < 0) return -1;

        if (req->error == RAW1394_ERROR_COMPAT && req->misc == 3) {
                h->protocol_version = 3;
                if (write(h->fd, req, sizeof(*req)) < 0) return -1;
                if (read(h->fd, req, sizeof(*req)) < 0) return -1;
        }

        if (req->error) {
                errno = 0;
                return -1;
        }

        return req->generation;
}


/**
 * raw1394_new_handle - create new handle
 *
 * Creates and returns a new handle which can (after being set up) control one
 * port.  It is not allowed to use the same handle in multiple threads or forked
 * processes.  It is allowed to create and use multiple handles, however.  Use
 * one handle per thread which needs it in the multithreaded case.
 *
 * Returns the created handle or %NULL when initialization fails.  In the latter
 * case errno either contains some OS specific error code or %0 if the error is
 * that libraw1394 and raw1394 don't support each other's protocol versions.
 **/
struct raw1394_handle *raw1394_new_handle(void)
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
        if (handle->generation == -1) {
                close(handle->fd);
                free(handle);
                return NULL;
        }

        handle->err = 0;
        handle->bus_reset_handler = bus_reset_default;
        handle->tag_handler = tag_handler_default;
        handle->arm_tag_handler = arm_tag_handler_default;
        memset(handle->iso_handler, 0, sizeof(handle->iso_handler));
        return handle;
}

/**
 * raw1394_destroy_handle - deallocate handle
 * @handle: handle to deallocate
 *
 * Closes connection with raw1394 on this handle and deallocates everything
 * associated with it.  It is safe to pass %NULL as handle, nothing is done in
 * this case.
 **/
void raw1394_destroy_handle(struct raw1394_handle *handle)
{
        if (handle) {
                close(handle->fd);
                free(handle);
        }
}

/**
 * raw1394_get_fd - get the communication file descriptor
 * @handle: raw1394 handle
 *
 * Returns the fd used for communication with the raw1394 kernel module.  This
 * can be used for select()/poll() calls if you wait on other fds or can be
 * integrated into another event loop (e.g. from a GUI application framework).
 * It can also be used to set/remove the O_NONBLOCK flag using fcntl() to modify
 * the blocking behaviour in raw1394_loop_iterate().  It must not be used for
 * anything else.
 **/
int raw1394_get_fd(struct raw1394_handle *handle)
{
        return handle->fd;
}

/**
 * raw1394_get_generation - get generation number of handle
 *
 * This function returns the generation number associated with the handle.  The
 * generation number is incremented on every bus reset, and every transaction
 * started by raw1394 is tagged with the stored generation number.  If these
 * don't match, the transaction will abort with an error.
 *
 * The generation number of the handle is not automatically updated,
 * raw1394_update_generation() has to be used for this.
 **/
unsigned int raw1394_get_generation(struct raw1394_handle *handle)
{
        return handle->generation;
}

/**
 * raw1394_update_generation - set generation number of handle
 * @gen: new generation number
 *
 * This function sets the generation number of the handle to @gen.  All requests
 * that apply to a single node ID are tagged with this number and abort with an
 * error if that is different from the generation number kept in the kernel.
 * This avoids acting on the wrong node which may have changed its ID in a bus
 * reset.
 *
 * TODO HERE
 **/
void raw1394_update_generation(struct raw1394_handle *handle, unsigned int gen)
{
        handle->generation = gen;
}

/**
 * raw1394_get_nodecount - get number of nodes on the bus
 * @handle: libraw1394 handle
 *
 * Returns the number of nodes on the bus to which the handle is connected.
 * This value can change with every bus reset.  Since the root node always has
 * the highest node ID, this number can be used to determine that ID (it's
 * LOCAL_BUS|(count-1)).
 **/
int raw1394_get_nodecount(struct raw1394_handle *handle)
{
        return handle->num_of_nodes;
}

/**
 * raw1394_get_local_id - get local node ID
 * @handle: libraw1394 handle
 *
 * Returns the node ID of the local node connected to which the handle is
 * connected.  This value can change with every bus reset.
 **/
nodeid_t raw1394_get_local_id(struct raw1394_handle *handle)
{
        return handle->local_id;
}

/**
 * raw1394_get_irm_id - get node ID of isochronous resource manager
 * @handle: libraw1394 handle
 *
 * Returns the node ID of the isochronous resource manager of the bus the handle
 * is connected to.  This value may change with every bus reset.
 **/
nodeid_t raw1394_get_irm_id(struct raw1394_handle *handle)
{
        return handle->irm_id;
}

/**
 * raw1394_set_userdata - associate user data with a handle
 * @handle: raw1394 handle
 * @data: user data (pointer)
 *
 * Allows to associate one void pointer with a handle.  libraw1394 does not care
 * about the data, it just stores it in the handle allowing it to be retrieved
 * at any time with raw1394_get_userdata().  This can be useful when multiple
 * handles are used, so that callbacks can identify the handle.
 **/
void raw1394_set_userdata(struct raw1394_handle *handle, void *data)
{
        handle->userdata = data;
}

/**
 * raw1394_get_userdata - retrieve user data from handle
 * @handle: libraw1394 handle
 *
 * Returns the user data pointer associated with the handle using
 * raw1394_set_userdata().
 **/
void *raw1394_get_userdata(struct raw1394_handle *handle)
{
        return handle->userdata;
}

/**
 * raw1394_get_port_info - get information about available ports
 * @pinf: pointer to an array of struct raw1394_portinfo
 * @maxports: number of elements in @pinf
 *
 * Before you can set which port to use, you have to use this function to find
 * out which ports exist.
 *
 * If your program is interactive, you should present the user with this list to
 * let them decide which port to use if there is more than one.  A
 * non-interactive program (and probably interactive ones, too) should provide a
 * command line option to choose the port.
 *
 * Returns the number of ports and writes information about them into @pinf, but
 * not into more than @maxports elements.  If @maxports is %0, @pinf can be
 * %NULL, too.
 **/
int raw1394_get_port_info(struct raw1394_handle *handle, 
                          struct raw1394_portinfo *pinf, int maxports)
{
        int num;
        struct raw1394_request *req = &handle->req;
        struct raw1394_khost_list *khl;

        CLEAR_REQ(req);
        req->type = RAW1394_REQ_LIST_CARDS;
        req->generation = handle->generation;
        req->recvb = ptr2int(handle->buffer);
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


/**
 * raw1394_set_port - choose port for handle
 * @port: port to connect to (corresponds to index of struct raw1394_portinfo)
 *
 * This function connects the handle to the port given (as queried with
 * raw1394_get_port_info()).  If successful, raw1394_get_port_info() and
 * raw1394_set_port() are not allowed to be called afterwards on this handle.
 * To make up for this, all the other functions (those handling asynchronous and
 * isochronous transmissions) can now be called.
 *
 * Returns %0 for success and -1 for failure with errno set appropriately.  A
 * possible failure mode is with errno = %ESTALE, in this case the configuration
 * has changed since the call to raw1394_get_port_info() and it has to be called
 * again to update your view of the available ports.
 **/
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
                if (handle->protocol_version == 3) {
                        handle->num_of_nodes = req->misc & 0xffff;
                        handle->local_id = req->misc >> 16;
                } else {
                        handle->num_of_nodes = req->misc & 0xff;
                        handle->irm_id = ((req->misc >> 8) & 0xff) | 0xffc0;
                        handle->local_id = req->misc >> 16;
                }
                handle->generation = req->generation;
                return 0;
        default:
                errno = 0;
                return -1;
        }
}

int raw1394_reset_bus_new(struct raw1394_handle *handle, int type)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_RESET_BUS;
        req->generation = handle->generation;
        req->misc = type;
	
        if (write(handle->fd, req, sizeof(*req)) < 0) return -1;

        return 0; /* success */
}


/**
 * raw1394_reset_bus - initiate bus reset
 *
 * This function initiates a bus reset on the connected port.  Usually this is
 * not necessary and should be avoided, this function is here for low level bus
 * control and debugging.
 *
 * Returns %0 for success and -1 for failure with errno set appropriately.
 **/
int raw1394_reset_bus(struct raw1394_handle *handle)
{
        return raw1394_reset_bus_new (handle, RAW1394_LONG_RESET);
}

int raw1394_busreset_notify (struct raw1394_handle *handle, 
                             int off_on_switch)
{
        struct raw1394_request *req = &handle->req;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_RESET_NOTIFY;
        req->generation = handle->generation;
        req->misc = off_on_switch;

        if (write(handle->fd, req, sizeof(*req)) < 0) return -1;

        return 0; /* success */
}

int raw1394_update_config_rom(raw1394handle_t handle, const quadlet_t
        *new_rom, size_t size, unsigned char rom_version)
{
        struct raw1394_request *req = &handle->req;
        int status;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_UPDATE_ROM;
        req->sendb = (unsigned long) new_rom;
        req->length = size;
        req->misc = rom_version;
        req->recvb = (unsigned long) &status;

        if (write(handle->fd, req, sizeof(*req)) < 0) return -8;

        return status;
}

int raw1394_get_config_rom(raw1394handle_t handle, quadlet_t *buffer,
        size_t buffersize, size_t *rom_size, unsigned char *rom_version)
{
        struct raw1394_request *req = &handle->req;
        int status;

        CLEAR_REQ(req);

        req->type = RAW1394_REQ_GET_ROM;
        req->recvb = (unsigned long) buffer;
        req->length = buffersize;
        req->tag = (unsigned long) rom_size;
        req->address = (unsigned long) rom_version;
        req->sendb = (unsigned long) &status;

        if (write(handle->fd, req, sizeof(*req)) < 0) return -8;

        return status;
}
