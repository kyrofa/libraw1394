
#ifndef _LIBRAW1394_RAW1394_H
#define _LIBRAW1394_RAW1394_H

#include <sys/types.h>
typedef u_int32_t quadlet_t;
typedef u_int64_t octlet_t;
typedef u_int64_t nodeaddr_t;
typedef u_int16_t nodeid_t;

typedef struct raw1394_handle *raw1394handle_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef int raw1394_errcode_t;
#define raw1394_make_errcode(ack, rcode) (((ack) << 16) | rcode)
#define raw1394_internal_err(errcode) ((errcode) < 0)
#define raw1394_get_ack(errcode) ((errcode) >> 16)
#define raw1394_get_rcode(errcode) ((errcode) & 0xf)
#define raw1394_get_internal(errcode) (errcode)
raw1394_errcode_t raw1394_get_errcode(raw1394handle_t);
int raw1394_errcode_to_errno(raw1394_errcode_t);

/*
 * Required as initialization.  One handle can control one port, it is possible
 * to use multiple handles.  raw1394_new_handle returns NULL for failure,
 * raw1394_destroy_handle accepts NULL.  If raw1394_new_handle returns NULL and
 * errno is 0, this version of libraw1394 is incompatible with the kernel.  
 */
raw1394handle_t raw1394_new_handle(void);
void raw1394_destroy_handle(raw1394handle_t handle);

/*
 * Get the fd of this handle to select()/poll() on it.  Don't try to mess around
 * with it any other way.  Valid only after the handle got attached to a port.
 */
int raw1394_get_fd(raw1394handle_t handle);

/*
 * Set and get user data.  This isn't used inside libraw1394, you can use it for
 * your own purposes.
 */
void *raw1394_get_userdata(raw1394handle_t handle);
void raw1394_set_userdata(raw1394handle_t handle, void *data);

nodeid_t raw1394_get_local_id(raw1394handle_t handle);
nodeid_t raw1394_get_irm_id(raw1394handle_t handle);

/* Get number of nodes on bus. */
int raw1394_get_nodecount(raw1394handle_t handle);

/*
 * Returns number of available ports (port == one IEEE 1394 card or onboard
 * chip).  A maximum number of maxport raw1394_portinfos will be filled out at
 * *pinf, zero is valid if you're only interested in the number of ports (which
 * is returned).
 */
struct raw1394_portinfo {
        int nodes;
        char name[32];
};

int raw1394_get_port_info(raw1394handle_t handle, struct raw1394_portinfo *pinf,
                          int maxports);

/*
 * Attach handle to port (counted from zero).  Returns zero for success or -1
 * for failure.  If in the case of failure errno is set to ESTALE the generation
 * number has changed and you should reget the port info.
 */
int raw1394_set_port(raw1394handle_t handle, int port);

/*
 * Reset the connected bus.  Returns -1 for failure, 0 for success.
 */
int raw1394_reset_bus(raw1394handle_t handle);

/*
 * Get one new message through handle and process it.  See below for handler
 * registering functions.  This function will return -1 for an error or the
 * return value of the handler which got executed.  Default handlers always
 * return zero.
 *
 * Note that some other library functions may call this function multiple times
 * to wait for their completion, some handler return values may get lost if you
 * use these.
 */
int raw1394_loop_iterate(raw1394handle_t handle);

/*
 * Set the handler that will be called when a bus reset message is encountered.
 * The default action is to just call raw1394_update_generation().  Returns old
 * handler.
 */
typedef int (*bus_reset_handler_t)(raw1394handle_t, unsigned int generation);
bus_reset_handler_t raw1394_set_bus_reset_handler(raw1394handle_t handle,
                                                  bus_reset_handler_t new_h);

/*
 * Since node IDs may change during a bus reset, generation numbers incremented
 * every bus reset are used to verify if a transaction request is intended for
 * this configuration.  If numbers don't match, they will fail immediately.
 *
 * raw1394_get_generation() returns the generation number in use by the handle,
 * not the current generation number.  The current generation number is passed
 * to the bus reset handler.
 */
unsigned int raw1394_get_generation(raw1394handle_t handle);
void raw1394_update_generation(raw1394handle_t handle, unsigned int generation);

/*
 * Set the handler that will be called when an async read/write/lock returns.
 * The default action is to call the callback in the raw1394_reqhandle pointed
 * to by tag.  Returns old handler.
 */
typedef int (*tag_handler_t)(raw1394handle_t, unsigned long tag,
                             raw1394_errcode_t err);
tag_handler_t raw1394_set_tag_handler(raw1394handle_t handle,
                                      tag_handler_t new_h);

/*
 * Set the handler that will be called when an iso packet arrives (data points
 * to the iso packet header).  The default action is to do nothing.
 *
 * Handlers have to be set separately for each channel, it is not possible to
 * set a handler when there is already one set for that channel.  Handlers can
 * be cleared by passing NULL for "new" parameter, in that case the old handler
 * will be returned.  Otherwise the return value is NULL for success and -1 for
 * failure.
 */
typedef int (*iso_handler_t)(raw1394handle_t, int channel, size_t length,
                             quadlet_t *data);
iso_handler_t raw1394_set_iso_handler(raw1394handle_t handle,
                                      unsigned int channel,
                                      iso_handler_t new_h);

/*
 * Set the handler that will be called when the local FCP_COMMAND or
 * FCP_RESPONSE register gets written to.  Returns old handler.
 *
 * The handler arg nodeid contains the node ID of the writer.  If response is 0
 * FCP_COMMAND was written, FCP_RESPONSE otherwise.
 */
typedef int (*fcp_handler_t)(raw1394handle_t, nodeid_t nodeid, int response,
                             size_t length, unsigned char *data);
fcp_handler_t raw1394_set_fcp_handler(raw1394handle_t, fcp_handler_t);

/*
 * This is the general request handle.  It is used by the default tag handler
 * when a request completes, it calls the callback and passes it the data
 * pointer and the error code of the request.
 */
typedef int (*req_callback_t)(raw1394handle_t, void *data,
                              raw1394_errcode_t err);
struct raw1394_reqhandle {
        req_callback_t callback;
        void *data;
};

/*
 * Passes custom tag.  Use pointer to raw1394_reqhandle if you use the standard
 * tag handler.
 */
int raw1394_start_read(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                       size_t length, quadlet_t *buffer, unsigned long tag);
int raw1394_start_write(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                        size_t length, quadlet_t *data, unsigned long tag);
int raw1394_start_lock(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                       unsigned int extcode, quadlet_t data, quadlet_t arg,
                       quadlet_t *result, unsigned long tag);
int raw1394_start_iso_write(raw1394handle_t handle, unsigned int channel,
                            unsigned int tag, unsigned int sy,
                            unsigned int speed, size_t length, quadlet_t *data,
                            unsigned long rawtag);

/*
 * This does the complete transaction and will return when it's finished.  It
 * will call raw1394_loop_iterate() as often as necessary, return values of
 * handlers called will be therefore lost.
 */
int raw1394_read(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                 size_t length, quadlet_t *buffer);
int raw1394_write(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                  size_t length, quadlet_t *data);
int raw1394_lock(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                 unsigned int extcode, quadlet_t data, quadlet_t arg,
                 quadlet_t *result);
int raw1394_iso_write(raw1394handle_t handle, unsigned int channel,
                      unsigned int tag, unsigned int sy, unsigned int speed,
                      size_t length, quadlet_t *data);

/*
 * Start and stop receiving a certain isochronous channel.  You have to set an
 * iso handler (see above).  You can receive multiple channels simultaneously.
 */
int raw1394_start_iso_rcv(raw1394handle_t handle, unsigned int channel);
int raw1394_stop_iso_rcv(raw1394handle_t handle, unsigned int channel);

/*
 * Start and stop receiving requests sent to the local FCP_COMMAND and
 * FCP_RESPONSE registers.
 */
int raw1394_start_fcp_listen(raw1394handle_t handle);
int raw1394_stop_fcp_listen(raw1394handle_t handle);


/*
 * Returns the version string.  Designed to be used by the autoconf macro to
 * detect the libraw version, not really intended for general use.
 */
const char *raw1394_get_libversion(void);

#ifdef __cplusplus
}
#endif

#endif /* _LIBRAW1394_RAW1394_H */
