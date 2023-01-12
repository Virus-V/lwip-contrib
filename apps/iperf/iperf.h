/* Iperf Example - iperf declaration

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef __IPERF_H_
#define __IPERF_H_

#ifdef __GNUC__
#include <sys/cdefs.h>
#endif /*__GNUC__*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPERF_IP_TYPE_IPV4 0
#define IPERF_IP_TYPE_IPV6 1
#define IPERF_TRANS_TYPE_TCP 0
#define IPERF_TRANS_TYPE_UDP 1

#define IPERF_FLAG_SET(cfg, flag) ((cfg) |= (flag))
#define IPERF_FLAG_CLR(cfg, flag) ((cfg) &= (~(flag)))

#define IPERF_FLAG_CLIENT (1)
#define IPERF_FLAG_SERVER (1 << 1)
#define IPERF_FLAG_TCP (1 << 2)
#define IPERF_FLAG_UDP (1 << 3)
#define IPERF_FLAG_DUAL (1 << 4)

#define IPERF_DEFAULT_PORT 5001
#define IPERF_DEFAULT_INTERVAL 1
#define IPERF_DEFAULT_TIME 10
#define IPERF_DEFAULT_NO_BW_LIMIT -1

#define IPERF_TRAFFIC_TASK_NAME "iperf_traffic"
#define IPERF_TRAFFIC_TASK_PRIORITY 4
#define IPERF_TRAFFIC_TASK_STACK 2048
#define IPERF_REPORT_TASK_NAME "iperf_report"
#define IPERF_REPORT_TASK_STACK 2048

#define IPERF_UDP_TX_LEN (1470)
#define IPERF_UDP_RX_LEN (1470)
#define IPERF_TCP_TX_LEN (4 << 10)
#define IPERF_TCP_RX_LEN (4 << 10)

#define IPERF_MAX_DELAY 64

#define IPERF_SOCKET_RX_TIMEOUT 10
#define IPERF_SOCKET_ACCEPT_TIMEOUT 5

typedef int esp_err_t;

/* Definitions for error constants. */
#define ESP_OK          0       /*!< esp_err_t value indicating success (no error) */
#define ESP_FAIL        -1      /*!< Generic esp_err_t code indicating failure */

typedef struct {
    uint32_t flag;
    union {
        uint32_t destination_ip4;
        char    *destination_ip6;
    };
    union {
        uint32_t source_ip4;
        char    *source_ip6;
    };
    uint8_t type;
    uint16_t dport;
    uint16_t sport;
    uint32_t interval;
    uint32_t time;
    uint16_t len_buf;
    int32_t bw_lim;
    uint8_t tos;
    uint8_t traffic_task_priority;
    uint32_t num_bytes;
} iperf_cfg_t;

esp_err_t iperf_start(iperf_cfg_t *cfg);

esp_err_t iperf_stop(void);

void lwshell_register_cmd_iperf(void);

#ifdef __cplusplus
}
#endif

#endif
