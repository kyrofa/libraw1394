
#ifndef _RAW1394_PRIVATE_H
#define _RAW1394_PRIVATE_H

struct raw1394_handle {
        int fd;
        unsigned int generation;

        nodeid_t local_id;
        int num_of_nodes;

        bus_reset_handler_t bus_reset_handler;
        tag_handler_t tag_handler;
        iso_handler_t iso_handler;

        struct raw1394_request req;
        quadlet_t buffer[2048];
};

#define HBUF_SIZE 8192
#define CLEAR_REQ(reqp) memset((reqp), 0, sizeof(struct raw1394_request))

#endif /* _RAW1394_PRIVATE_H */
