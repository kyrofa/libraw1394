/*
 * libraw1394 - library for raw access to the 1394 bus with the Linux subsystem.
 *
 * Copyright (C) 1999,2000,2001 Andreas Bombe
 *
 * This library is licensed under the GNU Lesser General Public License (LGPL),
 * version 2.1 or later. See the file COPYING.LIB in the distribution for
 * details.
 */

#include <config.h>

/* Variables to find version by linking (avoid need for test program) */

char __libraw1394_version_0_9;
char __libraw1394_version_0_9_0;

/* This function is to be used by the autoconf macro to find the lib version */
const char *raw1394_get_libversion()
{
        return VERSION;
}
