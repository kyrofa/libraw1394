
#include <stdio.h>
#include <errno.h>

#include "raw1394.h"
#include "csr.h"


#define TESTADDR (CSR_REGISTER_BASE + CSR_CYCLE_TIME)

const char not_compatible[] = "\
This libraw1394 does not work with your version of Linux. You need a different
version that matches your kernel (see kernel help text for the raw1394 option to
find out which is the correct version).\n";

const char not_loaded[] = "\
This probably means that you don't have raw1394 support in the kernel or that
you haven't loaded the raw1394 module.\n";


quadlet_t buffer;

int my_tag_handler(struct raw1394_handle *handle, unsigned long tag, int error)
{
        if (error < 0) {
                printf("completed with error %d\n", error);
        } else {
                printf("completed with 0x%08x, value 0x%08x\n", error, buffer);
        }

        return 0;
}



int main(int argc, char **argv)
{
        raw1394handle_t handle;
        int i, numcards;
        struct raw1394_portinfo pinf[16];

        tag_handler_t std_handler;
        int retval;


        handle = raw1394_get_handle();

        if (!handle) {
                if (!errno) {
                        printf(not_compatible);
                } else {
                        perror("couldn't get handle");
                        printf(not_loaded);
                }
                exit(1);
        }

        printf("successfully got handle\n");
        printf("current generation number: %d\n", raw1394_get_generation(handle));

        numcards = raw1394_get_port_info(handle, pinf, 16);
        if (numcards < 0) {
                perror("couldn't get card info");
                exit(1);
        } else {
                printf("%d card(s) found\n", numcards);
        }

        if (!numcards) {
                exit(0);
        }

        for (i = 0; i < numcards; i++) {
                printf("  nodes on bus: %2d, card name: %s\n", pinf[i].nodes,
                       pinf[i].name);
        }
        
        if (raw1394_set_port(handle, 0) < 0) {
                perror("couldn't set port");
                exit(1);
        }

        printf("using first card found: %d nodes on bus, local ID is %d\n",
               raw1394_get_nodecount(handle),
               raw1394_get_local_id(handle) & 0x3f);

        printf("\ndoing transactions with custom tag handler\n");
        std_handler = raw1394_set_tag_handler(handle, my_tag_handler);
        for (i = 0; i < pinf[0].nodes; i++) {
                printf("trying to send read request to node %d... ", i);
                fflush(stdout);
                buffer = 0;

                if (raw1394_start_read(handle, 0xffc0 | i, TESTADDR, 4,
                                       &buffer, 0) < 0) {
                        perror("failed");
                        continue;
                }
                raw1394_loop_iterate(handle);
        }

        printf("\nusing standard tag handler and synchronous calls\n");
        raw1394_set_tag_handler(handle, std_handler);
        for (i = 0; i < pinf[0].nodes; i++) {
                printf("trying to read from node %d... ", i);
                fflush(stdout);
                buffer = 0;

                retval = raw1394_read(handle, 0xffc0 | i, TESTADDR, 4, &buffer);
                if (retval < 0) {
                        printf("failed with error %d\n", retval);
                } else {
                        printf("completed with 0x%08x, value 0x%08x\n", retval,
                               buffer);
                }
        }

        exit(0);
}
