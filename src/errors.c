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
#include <errno.h>

#include "raw1394.h"
#include "kernel-raw1394.h"
#include "raw1394_private.h"
#include "ieee1394.h"


/**
 * raw1394_get_errcode - return error code of async transaction
 *
 * Returns the error code of the last raw1394_read(), raw1394_write(),
 * raw1394_lock() or raw1394_iso_write().  The error code is either an internal
 * error (i.e. not a bus error) or a combination of acknowledge code and
 * response code, as appropriate.
 *
 * Some macros are available to extract information from the error code,
 * raw1394_errcode_to_errno() can be used to convert it to an errno number of
 * roughly the same meaning.
 **/
raw1394_errcode_t raw1394_get_errcode(struct raw1394_handle *handle)
{
        return handle->err;
}

/**
 * raw1394_errcode_to_errno - convert libraw1394 errcode to errno
 * @errcode: the error code to convert
 *
 * The error code as retrieved by raw1394_get_errcode() is converted into a
 * roughly equivalent errno number and returned.  %0xdead is returned for an
 * illegal errcode.
 *
 * It is intended to be used to decide what to do (retry, give up, report error)
 * for those programs that aren't interested in details, since these get lost in
 * the conversion.  However the returned errnos are equivalent in source code
 * meaning only, the associated text of e.g. perror() is not necessarily
 * meaningful.
 *
 * Returned values are %EAGAIN (retrying might succeed, also generation number
 * mismatch), %EREMOTEIO (other node had internal problems), %EPERM (operation
 * not allowed on this address, e.g. write on read-only location), %EINVAL
 * (invalid argument) and %EFAULT (invalid pointer).
 **/
int raw1394_errcode_to_errno(raw1394_errcode_t errcode)
{
        static const int ack2errno[16] = {
                0xdead,    /* invalid ack code */
                0,         /* ack_complete */
                0xdead,    /* ack_pending, should not be used here */
                EAGAIN,    /* busy_x, busy_a and busy_b acks */
                EAGAIN,
                EAGAIN,
                0xdead,    /* invalid ack codes */
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                EREMOTEIO, /* ack_data_error */
                EPERM,     /* ack_type_error */
                0xdead     /* invalid ack code */
        };
        static const int rcode2errno[16] = {
                0,         /* rcode_complete */
                0xdead,    /* invalid rcodes */
                0xdead,
                0xdead,
                EAGAIN,    /* rcode_conflict_error */
                EREMOTEIO, /* rcode_data_error */
                EPERM,     /* rcode_type_error */
                EINVAL,    /* rcode_address_error */
                0xdead,    /* invalid rcodes */
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                0xdead,
                0xdead
        };

        if (!raw1394_internal_err(errcode)) {
                if (raw1394_get_ack(errcode) == 0x10
                    || raw1394_get_ack(errcode) == L1394_ACK_PENDING)
                        return rcode2errno[raw1394_get_rcode(errcode)];
                else
                        return ack2errno[raw1394_get_ack(errcode)];
        }

        switch (raw1394_get_internal(errcode)) {
        case RAW1394_ERROR_GENERATION:
        case RAW1394_ERROR_SEND_ERROR:
        case RAW1394_ERROR_ABORTED:
        case RAW1394_ERROR_TIMEOUT:
                return EAGAIN;

        case RAW1394_ERROR_MEMFAULT:
                return EFAULT;

        case RAW1394_ERROR_COMPAT:
        case RAW1394_ERROR_STATE_ORDER:
        case RAW1394_ERROR_INVALID_ARG:
        case RAW1394_ERROR_ALREADY:
        case RAW1394_ERROR_EXCESSIVE:
        case RAW1394_ERROR_UNTIDY_LEN:
        default:
                return EINVAL;
        }
}
