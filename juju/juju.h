/*						-*- c-basic-offset: 8 -*-
 *
 * juju.h -- Internal header file for raw1394 emulation
 *
 * Copyright (C) 2007  Kristian Hoegsberg <krh@bitplanet.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __juju_h
#define __juju_h

#include <stdlib.h>
#include <byteswap.h>
#include <fw-device-cdev.h>
#include "../src/raw1394.h"
#include "../src/csr.h"
#include "config.h"

#define ACK_COMPLETE 1

#define ptr_to_u64(p) ((__u64)(unsigned long)(p))
#define u64_to_ptr(p) ((void *)(unsigned long)(p))

static inline __u32
be32_to_cpu(__u32 q)
{
  union { char c[4]; __u32 q; } u = { { 1, 0, 0, 0 } };

  return u.q == 1 ? bswap_32(q) : q;
}

static inline __u32
cpu_to_be32(__u32 q)
{
  return be32_to_cpu(q);
}

#define ARRAY_LENGTH(a) (sizeof (a) / sizeof (a)[0])

#define BUFFER_SIZE	(16 * 1024)

#define MAX_PORTS 16

struct epoll_closure {
	int (*func)(raw1394handle_t handle,
		    struct epoll_closure *closure, __uint32_t events);
};

struct port {
	char device_file[32];
	char *name;
	int node_count;
	int card;
};

#define MAX_DEVICES	63
#define FILENAME_SIZE	16

struct device {
	struct epoll_closure closure;
	int fd;
	int node_id;
	int generation;
	char filename[FILENAME_SIZE];
};

struct request_closure {
	void *data;
	size_t length;
	unsigned long tag;
	struct raw1394_reqhandle reqhandle;
};

struct allocation;

struct raw1394_handle {
	struct port ports[MAX_PORTS];
	int port_count;
	int err;
	int generation;
	void *user_data;
	int notify_bus_reset;

	bus_reset_handler_t bus_reset_handler;
	tag_handler_t tag_handler;
	arm_tag_handler_t arm_tag_handler;
	fcp_handler_t fcp_handler;
	__u32 fcp_allocation_handle;
	struct allocation *allocations;

	int epoll_fd;
	int inotify_fd;
	int inotify_watch;
	int pipe_fds[2];

	struct epoll_closure pipe_closure;
	struct epoll_closure inotify_closure;

	struct device devices[MAX_DEVICES];
	int nodes[MAX_DEVICES];
	int local_fd;
	char local_filename[FILENAME_SIZE];

	struct fw_cdev_event_bus_reset reset;

	struct {
		struct epoll_closure closure;
		int fd;
		int type;
		int irq_interval;
		int packet_phase;
		int packet_count;
		int buf_packets;
		int max_packet_size;
		int packet_header_index;
		int prebuffer;
		int start_on_cycle;
		enum raw1394_iso_dma_recv_mode recv_mode;
		raw1394_iso_xmit_handler_t xmit_handler;
		raw1394_iso_recv_handler_t recv_handler;
		unsigned char *buffer, *buffer_end, *head;
		unsigned char *tail, *first_payload;

		struct fw_cdev_iso_packet *packets;
	} iso;

	char buffer[BUFFER_SIZE];
};

#endif
