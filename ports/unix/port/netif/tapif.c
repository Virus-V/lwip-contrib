/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ethip6.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/snmp.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"

#include "netif/tapif.h"

#define IFCONFIG_BIN "/sbin/ifconfig "

#if defined(LWIP_UNIX_FREEBSD)
#include <net/if.h>
#include <net/if_tap.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>

#define DEVTAP_NAME "tap0"

#else /* others */
#error not support other system yet
#endif

/* Define those to better describe your network interface. */
#define IFNAME0 't'
#define IFNAME1 'p'

#ifndef TAPIF_DEBUG
#define TAPIF_DEBUG LWIP_DBG_OFF
#endif

struct tapif {
  /* Add whatever per-interface state that is needed here. */
  int fd;
};

/* Forward declarations. */
static void tapif_input(struct netif *netif);
#if !NO_SYS
static void tapif_thread(void *arg);
#endif /* !NO_SYS */

/*-----------------------------------------------------------------------------------*/
static void low_level_init(struct netif *netif) {
  struct tapif *tapif;
  char tapdev_path[64];

  char *preconfigured_tapif = getenv("PRECONFIGURED_TAPIF");
  if (preconfigured_tapif == NULL) {
    preconfigured_tapif = DEVTAP_NAME;
  }

  snprintf(tapdev_path, sizeof(tapdev_path), "/dev/%s", preconfigured_tapif);
  printf("Using interface %s\n", tapdev_path);

  tapif = (struct tapif *)netif->state;

  /* Obtain MAC address from network interface. */

  /* (We just fake an address...) */
  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x12;
  netif->hwaddr[2] = 0x34;
  netif->hwaddr[3] = 0x56;
  netif->hwaddr[4] = 0x78;
  netif->hwaddr[5] = 0xab;
  netif->hwaddr_len = 6;

  /* device capabilities */
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;

  tapif->fd = open(tapdev_path, O_RDWR);
  LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: fd %d\n", tapif->fd));
  if (tapif->fd == -1) {
    perror("open");
    exit(1);
  }

  char commands[1024];
  snprintf(commands, sizeof(commands),
           "/sbin/ifconfig %s inet %d.%d.%d.%d netmask %d.%d.%d.%d up",
           preconfigured_tapif, ip4_addr1(netif_ip4_gw(netif)),
           ip4_addr2(netif_ip4_gw(netif)), ip4_addr3(netif_ip4_gw(netif)),
           ip4_addr4(netif_ip4_gw(netif)), ip4_addr1(netif_ip4_netmask(netif)),
           ip4_addr2(netif_ip4_netmask(netif)),
           ip4_addr3(netif_ip4_netmask(netif)),
           ip4_addr4(netif_ip4_netmask(netif)));

  printf("exec: %s\n", commands);

  int ret = system(commands);
  if (ret < 0) {
    perror("ifconfig failed");
    exit(1);
  }

  netif_set_link_up(netif);
  netif_set_up(netif);

#if !NO_SYS
  sys_thread_new("tapif_thread", tapif_thread, netif, DEFAULT_THREAD_STACKSIZE,
                 DEFAULT_THREAD_PRIO);
#endif /* !NO_SYS */
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t low_level_output(struct netif *netif, struct pbuf *p) {
  struct tapif *tapif = (struct tapif *)netif->state;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  ssize_t written;

  if (p->tot_len > sizeof(buf)) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("tapif: packet too large");
    return ERR_IF;
  }

  /* initiate transfer(); */
  pbuf_copy_partial(p, buf, p->tot_len, 0);

  /* signal that packet should be sent(); */
  written = write(tapif->fd, buf, p->tot_len);
  if (written < p->tot_len) {
    MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
    perror("tapif: write");
    return ERR_IF;
  } else {
    MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t)written);
    return ERR_OK;
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *low_level_input(struct netif *netif) {
  struct pbuf *p;
  u16_t len;
  ssize_t readlen;
  char buf[1518]; /* max packet size including VLAN excluding CRC */
  struct tapif *tapif = (struct tapif *)netif->state;

  /* Obtain the size of the packet and put it into the "len"
     variable. */
  readlen = read(tapif->fd, buf, sizeof(buf));
  if (readlen < 0) {
    perror("read returned -1");
    exit(1);
  }
  len = (u16_t)readlen;

  MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  if (p != NULL) {
    pbuf_take(p, buf, len);
    /* acknowledge that packet has been read(); */
  } else {
    /* drop packet(); */
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: could not allocate pbuf\n"));
  }

  return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * tapif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void tapif_input(struct netif *netif) {
  struct pbuf *p = low_level_input(netif);

  if (p == NULL) {
#if LINK_STATS
    LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
    LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_input: low_level_input returned NULL\n"));
    return;
  }

  if (netif->input(p, netif) != ERR_OK) {
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: netif input error\n"));
    pbuf_free(p);
  }
}
/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t tapif_init(struct netif *netif) {
  struct tapif *tapif = (struct tapif *)mem_malloc(sizeof(struct tapif));

  if (tapif == NULL) {
    LWIP_DEBUGF(NETIF_DEBUG, ("tapif_init: out of memory for tapif\n"));
    return ERR_MEM;
  }
  netif->state = tapif;
  MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
#if LWIP_IPV4
  netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
  netif->linkoutput = low_level_output;
  netif->mtu = 1500;

  low_level_init(netif);

  return ERR_OK;
}

/*-----------------------------------------------------------------------------------*/
void tapif_poll(struct netif *netif) { tapif_input(netif); }

#if NO_SYS
int tapif_select(struct netif *netif) {
  fd_set fdset;
  int ret;
  struct timeval tv;
  struct tapif *tapif;
  u32_t msecs = sys_timeouts_sleeptime();

  tapif = (struct tapif *)netif->state;

  tv.tv_sec = msecs / 1000;
  tv.tv_usec = (msecs % 1000) * 1000;

  FD_ZERO(&fdset);
  FD_SET(tapif->fd, &fdset);

  ret = select(tapif->fd + 1, &fdset, NULL, NULL, &tv);
  if (ret > 0) {
    tapif_input(netif);
  }
  return ret;
}

#else /* NO_SYS */

static void tapif_thread(void *arg) {
  struct netif *netif;
  struct tapif *tapif;
  fd_set fdset;
  int ret;

  netif = (struct netif *)arg;
  tapif = (struct tapif *)netif->state;

  while (1) {
    FD_ZERO(&fdset);
    FD_SET(tapif->fd, &fdset);

    /* Wait for a packet to arrive. */
    ret = select(tapif->fd + 1, &fdset, NULL, NULL, NULL);

    if (ret == 1) {
      /* Handle incoming packet. */
      tapif_input(netif);
    } else if (ret == -1) {
      perror("tapif_thread: select");
    }
  }
}

#endif /* NO_SYS */
