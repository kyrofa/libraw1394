#ifndef _LIBRAW1394_RAW1394_H
#define _LIBRAW1394_RAW1394_H

#define ARM_READ  1
#define ARM_WRITE 2
#define ARM_LOCK  4

#define RAW1394_LONG_RESET  0
#define RAW1394_SHORT_RESET 1

/* busresetnotify ... */
#define RAW1394_NOTIFY_OFF 0
#define RAW1394_NOTIFY_ON  1

#include <sys/types.h>
typedef u_int8_t  byte_t;
typedef u_int32_t quadlet_t;
typedef u_int64_t octlet_t;
typedef u_int64_t nodeaddr_t;
typedef u_int16_t nodeid_t;
typedef u_int8_t  phyid_t;
typedef u_int8_t  arm_options_t;
typedef u_int16_t arm_length_t;

typedef struct raw1394_handle *raw1394handle_t;

typedef struct arm_request {
        nodeid_t        destination_nodeid;
        nodeid_t        source_nodeid;
        nodeaddr_t      destination_offset;
        u_int8_t        tlabel;
        u_int8_t        tcode;
        u_int8_t        extended_transaction_code;
        u_int32_t       generation;
        arm_length_t    buffer_length;
        byte_t          *buffer;
} *arm_request_t;

typedef struct arm_response {
        int             response_code;
        arm_length_t    buffer_length;
        byte_t          *buffer;
} *arm_response_t;

typedef struct arm_request_response {
        struct arm_request  *request;
        struct arm_response *response;
} *arm_request_response_t;

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
 * Switch off/on busreset-notification for handle
 * return-value:
 * ==0 success 
 * !=0 failure
 * off_on_switch .... RAW1394_NOTIFY_OFF or RAW1394_NOTIFY_ON 
 */
int raw1394_busreset_notify (raw1394handle_t handle, int off_on_switch);

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
 * Reset the connected bus (with certain type). 
 * return-value:
 * -1 failure 
 * 0  success
 * type .... RAW1394_SHORT_RESET or RAW1394_LONG_RESET
 */
int raw1394_reset_bus_new(raw1394handle_t handle, int type);

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
 * Set the handler that will be called when an async read/write/lock arm_request
 * arrived. The default action is to call the arm_callback in the 
 * raw1394_arm_reqhandle pointed to by arm_tag.  Returns old handler.
 */
typedef int (*arm_tag_handler_t)(raw1394handle_t handle, unsigned long arm_tag,
                             byte_t request_type, unsigned int requested_length,
                             void *data); 
arm_tag_handler_t raw1394_set_arm_tag_handler(raw1394handle_t handle,
                                      arm_tag_handler_t new_h);

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
 * This is the genereal arm-request handle. (arm...address range mapping)
 * It is used by the default arm-tag handler when a request has been 
 * received, it calls the arm_callback.
 */
typedef int (*arm_req_callback_t) (raw1394handle_t,
                                   struct arm_request_response *arm_req_resp,
                                   unsigned int requested_length,
                                   void *pcontext, byte_t request_type);

struct raw1394_arm_reqhandle {
        arm_req_callback_t arm_callback;
        void *pcontext;
};

/*
 * AdressRangeMapping REGISTERING:
 * start, length .... identifies addressrange
 * *initial_value ... pointer to buffer containing (if necessary) initial value
 *                    NULL means undefined
 * arm_tag .......... identifier for arm_tag_handler 
 *                    (usually pointer to raw1394_arm_reqhandle)
 * access_rights .... access-rights for registered addressrange handled 
 *                    by kernel-part. Value is one or more binary or of the 
 *                    following flags: ARM_READ, ARM_WRITE, ARM_LOCK
 * notification_options ... identifies for which type of request you want
 *                    to be notified. Value is one or more binary or of the 
 *                    following flags: ARM_READ, ARM_WRITE, ARM_LOCK
 * client_transactions ... identifies for which type of request you want
 *                    to handle the request by the client application.
 *                    for those requests no response will be generated, but
 *                    has to be generated by the application.
 *                    Value is one or more binary or of the 
 *                    following flags: ARM_READ, ARM_WRITE, ARM_LOCK
 *                    For each bit set here, notification_options and
 *                    access_rights will be ignored.
 * returnvalue:       0  ... success
 *                    <0 ... failure
 */
int raw1394_arm_register(struct raw1394_handle *handle, nodeaddr_t start, 
                         size_t length, byte_t *initial_value,
                         octlet_t arm_tag, arm_options_t access_rights,
                         arm_options_t notification_options,
                         arm_options_t client_transactions);
/*
 * AdressRangeMapping UNREGISTERING:
 * start ............ identifies addressrange for unregistering 
 *                    (value of start have to be the same value 
 *                    used for registering this adressrange)
 * returnvalue:       0  ... success
 *                    <0 ... failure
 */
int raw1394_arm_unregister(raw1394handle_t handle, nodeaddr_t start);

/* 
 * send an echo request to the driver. the driver then send back the
 * same request. raw1394_loop_iterate will return data as return value,
 * when it processes the echo. 
 *
 * data:              arbitrary data; raw1394_loop_iterate will return it
 * returnvalue:       0 .... success
 *                    <0 ... failure
 */
int raw1394_echo_request(struct raw1394_handle *handle, quadlet_t data);

/* 
 * wake up raw1394_loop_iterate (or a blocking read from the device
 * file). actually this calls raw1394_echo_request with 0 as data. 
 *
 * returnvalue:       0 .... success
 *                    <0 ... failure
 */
int raw1394_wake_up(raw1394handle_t handle);

 
/* 
 * send physical request such as linkon, physicalconfigurationpacket ... etc.
 *
 * returnvalue:       0 .... success
 *                    <0 ... failure
 */
int raw1394_phy_packet_write (raw1394handle_t handle, quadlet_t data);
int raw1394_start_phy_packet_write(raw1394handle_t handle, 
        quadlet_t data, unsigned long tag);

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
int raw1394_start_lock64(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                       unsigned int extcode, octlet_t data, octlet_t arg,
                       octlet_t *result, unsigned long tag);
int raw1394_start_iso_write(raw1394handle_t handle, unsigned int channel,
                            unsigned int tag, unsigned int sy,
                            unsigned int speed, size_t length, quadlet_t *data,
                            unsigned long rawtag);


/* This starts sending an arbitrary async packet. It gets an array of quadlets consisting of
   header and data (without CRC in between). Header information is always in machine byte order,
   data (data block as well as quadlet data in a read response for data quadlet) shall be in
   big endian byte order. expect_response indicates, if we expect a response (i.e. if we will
   get the tag back after the packet was sent or after a response arrived). length is the length
   of the complete packet (header_length + length of the data block).
   The main purpose of this function is to send responses for incoming transactions, that
   are handled by the application.
   Do not use that function, unless you really know, what you do! Sending corrupt packet may
   lead to weird results.
*/
int raw1394_start_async_send(raw1394handle_t handle,
                             size_t length, size_t header_length, unsigned int expect_response,
                             quadlet_t *data, unsigned long rawtag);

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
int raw1394_lock64(raw1394handle_t handle, nodeid_t node, nodeaddr_t addr,
                 unsigned int extcode, octlet_t data, octlet_t arg,
                 octlet_t *result);
int raw1394_iso_write(raw1394handle_t handle, unsigned int channel,
                      unsigned int tag, unsigned int sy, unsigned int speed,
                      size_t length, quadlet_t *data);
int raw1394_async_send(raw1394handle_t handle,
                             size_t length, size_t header_length, unsigned int expect_response,
                             quadlet_t *data);

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


/* updates the configuration rom of a host. rom_version must be the current
 * version, otherwise it will fail with return value -1. 
 * Return value -2 indicates that the new rom version is too big.
 * Return value 0 indicates success
*/

int raw1394_update_config_rom(raw1394handle_t handle, const quadlet_t
        *new_rom, size_t size, unsigned char rom_version);


/* reads the current version of the configuration rom of a host. 
 * buffersize is the size of the buffer, rom_size
 * returns the size of the current rom image.. rom_version is the
 * version number of the fetched rom.
 * return value -1 indicates, that the buffer was too small, 
 * 0 indicates success.
 */

int raw1394_get_config_rom(raw1394handle_t handle, quadlet_t *buffer,
        size_t buffersize, size_t *rom_size, unsigned char *rom_version);

#ifdef __cplusplus
}
#endif

#endif /* _LIBRAW1394_RAW1394_H */
