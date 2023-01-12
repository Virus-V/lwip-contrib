/* Iperf Example - iperf implementation

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "iperf/iperf.h"

#define xTaskCreatePinnedToCore(pvTaskCode, pcName, usStackDepth, pvParameters, uxPriority, pvCreatedTask, xCoreID_) sys_thread_new(pcName, pvTaskCode, pvParameters, usStackDepth, uxPriority)
#define esp_timer_get_time get_time_now_us
#define esp_rom_delay_us(x) do { int _n = (x); while(_n--);}while(0) ;
#define IRAM_ATTR
#define IPERF_V6 0 // TODO sync with lwip config

#define NL "\r\n"
#define NEWLINE "\r\n"

/**
 * Macro which can be used to check the condition. If the condition is not 'true', it prints the message,
 * sets the local variable 'ret' to the supplied 'err_code', and then exits by jumping to 'goto_tag'.
 */
#define GOTO_ON_FALSE(a, err_code, goto_tag, log_tag, format, ...) do {                     \
        (void)log_tag;                                                                          \
        if ((!(a))) {                                                                   \
            ret = err_code;                                                                     \
            goto goto_tag;                                                                      \
        }                                                                                       \
    } while (0)

#define ESP_LOGI(...) printf("Info(%s): %s\r\n", __VA_ARGS__)
#define ESP_LOGW(...) printf("Warn(%s): %s\r\n", __VA_ARGS__)
#define ESP_LOGE(...) printf("Error(%s): %s\r\n", __VA_ARGS__)

typedef struct {
    iperf_cfg_t cfg;
    bool finish;
    uint32_t actual_len;
    uint32_t tot_len;
    uint32_t buffer_len;
    uint8_t *buffer;
    uint32_t sockfd;
} iperf_ctrl_t;

static bool s_iperf_is_running = false;
static iperf_ctrl_t s_iperf_ctrl;
static const char *TAG = "iperf";

uint64_t get_time_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

inline static bool iperf_is_udp_client(void)
{
    return ((s_iperf_ctrl.cfg.flag & IPERF_FLAG_CLIENT) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_UDP));
}

inline static bool iperf_is_udp_server(void)
{
    return ((s_iperf_ctrl.cfg.flag & IPERF_FLAG_SERVER) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_UDP));
}

inline static bool iperf_is_tcp_client(void)
{
    return ((s_iperf_ctrl.cfg.flag & IPERF_FLAG_CLIENT) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_TCP));
}

inline static bool iperf_is_tcp_dual_client(void)
{
    return ((s_iperf_ctrl.cfg.flag & IPERF_FLAG_CLIENT) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_TCP) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_DUAL));
}

inline static bool iperf_is_tcp_server(void)
{
    return ((s_iperf_ctrl.cfg.flag & IPERF_FLAG_SERVER) && (s_iperf_ctrl.cfg.flag & IPERF_FLAG_TCP));
}

static int iperf_get_socket_error_code(int sockfd)
{
    return errno;
}

static int iperf_show_socket_error_reason(const char *str, int sockfd)
{
    int err = errno;
    if (err != 0) {
        ESP_LOGW(TAG, "%s error, error code: %d, reason: %s", str, err, strerror(err));
    }

    return err;
}

static void iperf_report_task(void *arg)
{
    uint32_t interval = s_iperf_ctrl.cfg.interval;
    uint32_t time = s_iperf_ctrl.cfg.time;
    uint32_t delay_interval = (interval * 1000);
    uint32_t cur = 0;
    double average = 0;
    double actual_bandwidth = 0;
    double actual_transfer = 0;
    int k = 1;

    printf("[ ID] Interval       Transfer     Bandwidth"NEWLINE);
    while (!s_iperf_ctrl.finish) {
        usleep(delay_interval * 1000);
        actual_bandwidth = (s_iperf_ctrl.actual_len / 1e6 * 8) / interval;
        actual_transfer = s_iperf_ctrl.actual_len / 1e6;
        printf("[%3d] %2d.0-%2d.0 sec  %.2f MByte  %.2f Mbits/sec"NEWLINE,
                s_iperf_ctrl.sockfd, cur, cur + interval, actual_transfer, actual_bandwidth);
        cur += interval;
        average = ((average * (k - 1) / k) + (actual_bandwidth / k));
        k++;
        s_iperf_ctrl.actual_len = 0;
        if (cur >= time) {
            actual_transfer = s_iperf_ctrl.tot_len / 1e6;
            printf("[%3d] %2d.0-%2d.0 sec  %.2f MByte  %.2f Mbits/sec"NEWLINE,
                s_iperf_ctrl.sockfd, 0, time, actual_transfer, average);
            break;
        }
    }

    s_iperf_ctrl.finish = true;
    return;
}

static esp_err_t iperf_start_report(void)
{
    int ret;

    ret = xTaskCreatePinnedToCore(iperf_report_task, IPERF_REPORT_TASK_NAME, IPERF_REPORT_TASK_STACK, NULL, s_iperf_ctrl.cfg.traffic_task_priority + 1, NULL, portNUM_PROCESSORS - 1);

    if (ret == NULL) {
        ESP_LOGE(TAG, "create task %s failed", IPERF_REPORT_TASK_NAME);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void socket_recv(int recv_socket, struct sockaddr_storage listen_addr, uint8_t type)
{
    bool iperf_recv_start = true;
    uint8_t *buffer;
    int want_recv = 0;
    int actual_recv = 0;
#if IPERF_V6
    socklen_t socklen = (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
#else
    socklen_t socklen = sizeof(struct sockaddr_in);
#endif
    const char *error_log = (type == IPERF_TRANS_TYPE_TCP) ? "tcp server recv" : "udp server recv";

    buffer = s_iperf_ctrl.buffer;
    want_recv = s_iperf_ctrl.buffer_len;
    while (!s_iperf_ctrl.finish) {
        actual_recv = recvfrom(recv_socket, buffer, want_recv, 0, (struct sockaddr *)&listen_addr, &socklen);
        if (actual_recv < 0) {
            iperf_show_socket_error_reason(error_log, recv_socket);
            s_iperf_ctrl.finish = true;
            break;
        } else {
            if (iperf_recv_start) {
                iperf_start_report();
                iperf_recv_start = false;
            }
            s_iperf_ctrl.actual_len += actual_recv;
            s_iperf_ctrl.tot_len += actual_recv;
            if (s_iperf_ctrl.cfg.num_bytes > 0 && s_iperf_ctrl.tot_len > s_iperf_ctrl.cfg.num_bytes) {
                break;
            }
        }
    }
}

static void socket_recv_dual(int recv_socket, struct sockaddr_storage listen_addr, uint8_t type)
{
    uint8_t *buffer;
    int want_recv = 0;
    int actual_recv = 0;
    socklen_t socklen = sizeof(struct sockaddr_in);

#define RECV_DUAL_BUF_LEN (4 * 1024)
    buffer = malloc(RECV_DUAL_BUF_LEN);
    want_recv = RECV_DUAL_BUF_LEN;
    if (!buffer) {
        return;
    }
    while (1) {
        actual_recv = recvfrom(recv_socket, buffer, want_recv, 0, (struct sockaddr *)&listen_addr, &socklen);
        if (actual_recv <= 0) {
            break;
        }
    }
    free(buffer);
}

typedef struct {
    int32_t flags;
    int32_t numThreads;
    int32_t mPort;
    int32_t bufferlen;
    int32_t mWindowSize;
    int32_t mAmount;
    int32_t mRate;
    int32_t mUDPRateUnits;
    int32_t mRealtime;
} iperf_client_hdr_t;
#define HEADER_VERSION1 0x80000000
#define RUN_NOW         0x00000001
#define UNITS_PPS       0x00000002

static void send_dual_header(int sock, struct sockaddr *addr, socklen_t socklen)
{
    iperf_client_hdr_t hdr = {};
    iperf_cfg_t *cfg = &s_iperf_ctrl.cfg;

    hdr.flags = htonl(HEADER_VERSION1 | RUN_NOW);
    hdr.numThreads = htonl(1);
    hdr.mPort = htonl(cfg->sport);
    hdr.mAmount = htonl(-(cfg->time * 100));

    sendto(sock, &hdr, sizeof(hdr), 0, addr, socklen);
}

static void socket_send(int send_socket, struct sockaddr_storage dest_addr, uint8_t type, int bw_lim)
{
    uint8_t *buffer;
    int32_t *pkt_id_p;
    int32_t pkt_cnt = 0;
    int actual_send = 0;
    int want_send = 0;
    int period_us = -1;
    int delay_us = 0;
    int64_t prev_time = 0;
    int64_t send_time = 0;
    int err = 0;
#if IPERF_V6
    const socklen_t socklen = (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
#else
    const socklen_t socklen = sizeof(struct sockaddr_in);
#endif
    const char *error_log = (type == IPERF_TRANS_TYPE_TCP) ? "tcp client send" : "udp client send";

    buffer = s_iperf_ctrl.buffer;
    pkt_id_p = (int32_t *)s_iperf_ctrl.buffer;
    want_send = s_iperf_ctrl.buffer_len;
    iperf_start_report();

    if (bw_lim > 0) {
        period_us = want_send * 8 / bw_lim;
    }

    if (iperf_is_tcp_dual_client()) {
        send_dual_header(send_socket, (struct sockaddr *)&dest_addr, socklen);
    }

    while (!s_iperf_ctrl.finish) {
        if (period_us > 0) {
            send_time = esp_timer_get_time();
            if (actual_send > 0){
                // Last packet "send" was successful, check how much off the previous loop duration was to the ideal send period. Result will adjust the
                // next send delay.
                delay_us += period_us + (int32_t)(prev_time - send_time);
            } else {
                // Last packet "send" was not successful. Ideally we should try to catch up the whole previous loop duration (e.g. prev_time - send_time).
                // However, that's not possible since the most probable reason why the send was unsuccessful is the HW was not able to process the packet.
                // Hence, we cannot queue more packets with shorter (or no) delay to catch up since we are already at the performance edge. The best we
                // can do is to reset the send delay (which is probably big negative number) and start all over again.
                delay_us = 0;
            }
            prev_time = send_time;
        }
        *pkt_id_p = htonl(pkt_cnt); // datagrams need to be sequentially numbered
        if (pkt_cnt >= INT32_MAX) {
            pkt_cnt = 0;
        }
        else {
            pkt_cnt++;
        }
        actual_send = sendto(send_socket, buffer, want_send, 0, (struct sockaddr *)&dest_addr, socklen);
        if (actual_send != want_send) {
            if (type == IPERF_TRANS_TYPE_UDP) {
                err = iperf_get_socket_error_code(send_socket);
                // ENOMEM is expected under heavy load => do not print it
                if (err != ENOMEM) {
                    iperf_show_socket_error_reason(error_log, send_socket);
                }
            } else if (type == IPERF_TRANS_TYPE_TCP) {
                iperf_show_socket_error_reason(error_log, send_socket);
                break;
            }
        } else {
            s_iperf_ctrl.actual_len += actual_send;
            s_iperf_ctrl.tot_len += actual_send;
            if (s_iperf_ctrl.cfg.num_bytes > 0 && s_iperf_ctrl.tot_len >= s_iperf_ctrl.cfg.num_bytes) {
                break;
            }
        }
        // The send delay may be negative, it indicates we are trying to catch up and hence to not delay the loop at all.
        if (delay_us > 0) {
            esp_rom_delay_us(delay_us);
        }
    }
}

static esp_err_t IRAM_ATTR iperf_run_tcp_server(void)
{
    int listen_socket = -1;
    int client_socket = -1;
    int opt = 1;
    int err = 0;
    esp_err_t ret = ESP_OK;
    struct sockaddr_in remote_addr;
    struct timeval timeout = { 0 };
    socklen_t addr_len = sizeof(struct sockaddr);
    struct sockaddr_storage listen_addr = { 0 };
#if IPERF_V6
    struct sockaddr_in6 listen_addr6 = { 0 };
#endif
    struct sockaddr_in listen_addr4 = { 0 };

    GOTO_ON_FALSE((s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6 || s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4), ESP_FAIL, exit, TAG, "Ivalid AF types");

#if IPERF_V6
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) {
        // The TCP server listen at the address "::", which means all addresses can be listened to.
        inet6_aton("::", &listen_addr6.sin6_addr);
        listen_addr6.sin6_family = AF_INET6;
        listen_addr6.sin6_port = htons(s_iperf_ctrl.cfg.sport);

        listen_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_IPV6);
        GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);

        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_socket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

        ESP_LOGI(TAG, "Socket created");

        err = bind(listen_socket, (struct sockaddr *)&listen_addr6, sizeof(listen_addr6));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d, IPPROTO: %d", errno, AF_INET6);
        err = listen(listen_socket, 1);
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Error occurred during listen: errno %d", errno);

        timeout.tv_sec = IPERF_SOCKET_RX_TIMEOUT;
        setsockopt(listen_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        memcpy(&listen_addr, &listen_addr6, sizeof(listen_addr6));
    } else
#endif
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4) {
        listen_addr4.sin_family = AF_INET;
        listen_addr4.sin_port = htons(s_iperf_ctrl.cfg.sport);
        listen_addr4.sin_addr.s_addr = s_iperf_ctrl.cfg.source_ip4;

        listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);

        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        ESP_LOGI(TAG, "Socket created");

        err = bind(listen_socket, (struct sockaddr *)&listen_addr4, sizeof(listen_addr4));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d, IPPROTO: %d", errno, AF_INET);

        err = listen(listen_socket, 5);
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Error occurred during listen: errno %d", errno);
        memcpy(&listen_addr, &listen_addr4, sizeof(listen_addr4));
    }

    client_socket = accept(listen_socket, (struct sockaddr *)&remote_addr, &addr_len);
    GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to accept connection: errno %d", errno);
    ESP_LOGI(TAG, "accept: %s,%d\n", inet_ntoa(remote_addr.sin_addr), htons(remote_addr.sin_port));

    timeout.tv_sec = IPERF_SOCKET_RX_TIMEOUT;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    socket_recv(client_socket, listen_addr, IPERF_TRANS_TYPE_TCP);
exit:
    if (client_socket != -1) {
        close(client_socket);
    }

    if (listen_socket != -1) {
        shutdown(listen_socket, 0);
        close(listen_socket);
        ESP_LOGI(TAG, "TCP Socket server is closed.");
    }
    s_iperf_ctrl.finish = true;
    return ret;
}

static void IRAM_ATTR iperf_tcp_dual_server_task(void *pvParameters)
{
    int listen_socket = -1;
    int client_socket = -1;
    int opt = 1;
    int err = 0;
    esp_err_t ret = ESP_OK;
    struct sockaddr_in remote_addr;
    struct timeval timeout = { 0 };
    socklen_t addr_len = sizeof(struct sockaddr);
    struct sockaddr_storage listen_addr = { 0 };
    struct sockaddr_in listen_addr4 = { 0 };

    (void)ret;
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4) {
        listen_addr4.sin_family = AF_INET;
        listen_addr4.sin_port = htons(s_iperf_ctrl.cfg.sport);
        listen_addr4.sin_addr.s_addr = s_iperf_ctrl.cfg.source_ip4;

        listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);

        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        ESP_LOGI(TAG, "Socket created");

        err = bind(listen_socket, (struct sockaddr *)&listen_addr4, sizeof(listen_addr4));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d, IPPROTO: %d", errno, AF_INET);

        err = listen(listen_socket, 5);
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Error occurred during listen: errno %d", errno);
        memcpy(&listen_addr, &listen_addr4, sizeof(listen_addr4));
    }

    client_socket = accept(listen_socket, (struct sockaddr *)&remote_addr, &addr_len);
    GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to accept connection: errno %d", errno);
    ESP_LOGI(TAG, "accept: %s,%d\n", inet_ntoa(remote_addr.sin_addr), htons(remote_addr.sin_port));

    timeout.tv_sec = IPERF_SOCKET_RX_TIMEOUT;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    socket_recv_dual(client_socket, listen_addr, IPERF_TRANS_TYPE_TCP);
exit:
    if (client_socket != -1) {
        close(client_socket);
    }

    if (listen_socket != -1) {
        shutdown(listen_socket, 0);
        close(listen_socket);
        ESP_LOGI(TAG, "TCP Socket server is closed.");
    }

    //vTaskDelete(NULL);
    return;
}

static esp_err_t iperf_run_tcp_client(void)
{
    int client_socket = -1;
    int err = 0;
    esp_err_t ret = ESP_OK;
    struct sockaddr_storage dest_addr = { 0 };
#if IPERF_V6
    struct sockaddr_in6 dest_addr6 = { 0 };
#endif
    struct sockaddr_in dest_addr4 = { 0 };
    int opt = s_iperf_ctrl.cfg.tos;

    GOTO_ON_FALSE((s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6 || s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4), ESP_FAIL, exit, TAG, "Ivalid AF types");

    if (iperf_is_tcp_dual_client()) {
        xTaskCreatePinnedToCore(iperf_tcp_dual_server_task, "dual_rx", IPERF_TRAFFIC_TASK_STACK, NULL, s_iperf_ctrl.cfg.traffic_task_priority, NULL, 0);
        usleep(100 * 1000); // delay 100ms
    }
#if IPERF_V6
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) {
        client_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_IPV6);
        GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        setsockopt(client_socket, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));


        inet6_aton(s_iperf_ctrl.cfg.destination_ip6, &dest_addr6.sin6_addr);
        dest_addr6.sin6_family = AF_INET6;
        dest_addr6.sin6_port = htons(s_iperf_ctrl.cfg.dport);

        err = connect(client_socket, (struct sockaddr *)&dest_addr6, sizeof(struct sockaddr_in6));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to connect: errno %d", errno);
        ESP_LOGI(TAG, "Successfully connected");
        memcpy(&dest_addr, &dest_addr6, sizeof(dest_addr6));
    } else
#endif
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4) {
        client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        setsockopt(client_socket, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));

        dest_addr4.sin_family = AF_INET;
        dest_addr4.sin_port = htons(s_iperf_ctrl.cfg.dport);
        dest_addr4.sin_addr.s_addr = s_iperf_ctrl.cfg.destination_ip4;
        err = connect(client_socket, (struct sockaddr *)&dest_addr4, sizeof(struct sockaddr_in));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to connect: errno %d", errno);
        ESP_LOGI(TAG, "Successfully connected");
        memcpy(&dest_addr, &dest_addr4, sizeof(dest_addr4));
    }

    socket_send(client_socket, dest_addr, IPERF_TRANS_TYPE_TCP, s_iperf_ctrl.cfg.bw_lim);
exit:
    if (client_socket != -1) {
        shutdown(client_socket, 0);
        close(client_socket);
        ESP_LOGI(TAG, "TCP Socket client is closed.");
    }
    s_iperf_ctrl.finish = true;
    return ret;
}

static esp_err_t IRAM_ATTR iperf_run_udp_server(void)
{
    int listen_socket = -1;
    int opt = 1;
    int err = 0;
    esp_err_t ret = ESP_OK;
    struct timeval timeout = { 0 };
    struct sockaddr_storage listen_addr = { 0 };
#if IPERF_V6
    struct sockaddr_in6 listen_addr6 = { 0 };
#endif
    struct sockaddr_in listen_addr4 = { 0 };

    GOTO_ON_FALSE((s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6 || s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4), ESP_FAIL, exit, TAG, "Ivalid AF types");

#if IPERF_V6
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) {
        // The UDP server listen at the address "::", which means all addresses can be listened to.
        inet6_aton("::", &listen_addr6.sin6_addr);
        listen_addr6.sin6_family = AF_INET6;
        listen_addr6.sin6_port = htons(s_iperf_ctrl.cfg.sport);

        listen_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        ESP_LOGI(TAG, "Socket created");

        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        err = bind(listen_socket, (struct sockaddr *)&listen_addr6, sizeof(struct sockaddr_in6));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d", errno);
        ESP_LOGI(TAG, "Socket bound, port %d", listen_addr6.sin6_port);

        memcpy(&listen_addr, &listen_addr6, sizeof(listen_addr6));
    } else
#endif
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4) {
        listen_addr4.sin_family = AF_INET;
        listen_addr4.sin_port = htons(s_iperf_ctrl.cfg.sport);
        listen_addr4.sin_addr.s_addr = s_iperf_ctrl.cfg.source_ip4;

        listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        ESP_LOGI(TAG, "Socket created");

        setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        err = bind(listen_socket, (struct sockaddr *)&listen_addr4, sizeof(struct sockaddr_in));
        GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d", errno);
        ESP_LOGI(TAG, "Socket bound, port %d", listen_addr4.sin_port);
        memcpy(&listen_addr, &listen_addr4, sizeof(listen_addr4));
    }

    timeout.tv_sec = IPERF_SOCKET_RX_TIMEOUT;
    setsockopt(listen_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    socket_recv(listen_socket, listen_addr, IPERF_TRANS_TYPE_UDP);
exit:
    if (listen_socket != -1) {
        shutdown(listen_socket, 0);
        close(listen_socket);
    }
    ESP_LOGI(TAG, "Udp socket server is closed.");
    s_iperf_ctrl.finish = true;
    return ret;
}

static esp_err_t iperf_run_udp_client(void)
{
    int client_socket = -1;
    int opt = 1;
    esp_err_t ret = ESP_OK;
    struct sockaddr_storage dest_addr = { 0 };
#if IPERF_V6
    struct sockaddr_in6 dest_addr6 = { 0 };
#endif
    struct sockaddr_in dest_addr4 = { 0 };

    GOTO_ON_FALSE((s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6 || s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4), ESP_FAIL, exit, TAG, "Ivalid AF types");

#if IPERF_V6
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV6) {
        inet6_aton(s_iperf_ctrl.cfg.destination_ip6, &dest_addr6.sin6_addr);
        dest_addr6.sin6_family = AF_INET6;
        dest_addr6.sin6_port = htons(s_iperf_ctrl.cfg.dport);

        client_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IPV6);
        GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        ESP_LOGI(TAG, "Socket created, sending to %s:%d", s_iperf_ctrl.cfg.destination_ip6, s_iperf_ctrl.cfg.dport);

        setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        opt = s_iperf_ctrl.cfg.tos;
        setsockopt(client_socket, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
        memcpy(&dest_addr, &dest_addr6, sizeof(dest_addr6));
    } else
#endif
    if (s_iperf_ctrl.cfg.type == IPERF_IP_TYPE_IPV4) {
        dest_addr4.sin_family = AF_INET;
        dest_addr4.sin_port = htons(s_iperf_ctrl.cfg.dport);
        dest_addr4.sin_addr.s_addr = s_iperf_ctrl.cfg.destination_ip4;

        client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);
        ESP_LOGI(TAG, "Socket created, sending to %d:%d", s_iperf_ctrl.cfg.destination_ip4, s_iperf_ctrl.cfg.dport);

        setsockopt(client_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        opt = s_iperf_ctrl.cfg.tos;
        setsockopt(client_socket, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
        memcpy(&dest_addr, &dest_addr4, sizeof(dest_addr4));
    }

    socket_send(client_socket, dest_addr, IPERF_TRANS_TYPE_UDP, s_iperf_ctrl.cfg.bw_lim);
exit:
    if (client_socket != -1) {
        shutdown(client_socket, 0);
        close(client_socket);
    }
    s_iperf_ctrl.finish = true;
    ESP_LOGI(TAG, "UDP Socket client is closed");
    return ret;
}

static void iperf_task_traffic(void *arg)
{
    if (iperf_is_udp_client()) {
        iperf_run_udp_client();
    } else if (iperf_is_udp_server()) {
        iperf_run_udp_server();
    } else if (iperf_is_tcp_client()) {
        iperf_run_tcp_client();
    } else {
        iperf_run_tcp_server();
    }

    if (s_iperf_ctrl.buffer) {
        free(s_iperf_ctrl.buffer);
        s_iperf_ctrl.buffer = NULL;
    }
    printf("iperf exit\r\n");
    s_iperf_is_running = false;
    return;
}

static uint32_t iperf_get_buffer_len(void)
{
    if (iperf_is_udp_client()) {
        return (s_iperf_ctrl.cfg.len_buf == 0 ? IPERF_UDP_TX_LEN : s_iperf_ctrl.cfg.len_buf);
    } else if (iperf_is_udp_server()) {
        return IPERF_UDP_RX_LEN;
    } else if (iperf_is_tcp_client()) {
        return (s_iperf_ctrl.cfg.len_buf == 0 ? IPERF_TCP_TX_LEN : s_iperf_ctrl.cfg.len_buf);
    } else {
        return (s_iperf_ctrl.cfg.len_buf == 0 ? IPERF_TCP_RX_LEN : s_iperf_ctrl.cfg.len_buf);
    }
    return 0;
}

static void net_iperf_print_header(iperf_cfg_t *cfg)
{
    printf("------------------------------------------------------------\r\n");
    if (iperf_is_udp_server()) {
        printf("Server listening on UDP port %d\r\n",
                    cfg->sport);
    } else if (iperf_is_tcp_server()) {
        printf("Server listening on TCP port %d\r\n",
                    cfg->sport);
    } else if (iperf_is_udp_client()) {
        printf("Client connecting to %s, UDP port %d\r\n"
                    "Sending %d byte datagrams\r\n", inet_ntoa(cfg->destination_ip4),
                    cfg->dport, cfg->num_bytes);
    } else if (iperf_is_tcp_client()) {
        printf("Client connecting to %s, TCP port %d\r\n",
                    inet_ntoa(cfg->destination_ip4), cfg->dport);
    }
    printf("------------------------------------------------------------\r\n");
}

esp_err_t iperf_start(iperf_cfg_t *cfg)
{
    int ret;

    if (!cfg) {
        return ESP_FAIL;
    }

    if (s_iperf_is_running) {
        ESP_LOGW(TAG, "iperf is running");
        printf("iperf is running\r\n");
        return ESP_FAIL;
    }

    memset(&s_iperf_ctrl, 0, sizeof(s_iperf_ctrl));
    memcpy(&s_iperf_ctrl.cfg, cfg, sizeof(*cfg));
    s_iperf_is_running = true;
    s_iperf_ctrl.finish = false;
    s_iperf_ctrl.buffer_len = iperf_get_buffer_len();
    s_iperf_ctrl.buffer = (uint8_t *)malloc(s_iperf_ctrl.buffer_len);
    if (!s_iperf_ctrl.buffer) {
        ESP_LOGE(TAG, "create buffer: not enough memory");
        return ESP_FAIL;
    }
    memset(s_iperf_ctrl.buffer, 0, s_iperf_ctrl.buffer_len);
    ret = xTaskCreatePinnedToCore(iperf_task_traffic, IPERF_TRAFFIC_TASK_NAME, IPERF_TRAFFIC_TASK_STACK, NULL, s_iperf_ctrl.cfg.traffic_task_priority, NULL, portNUM_PROCESSORS - 1);
    if (ret == NULL) {
        ESP_LOGE(TAG, "create task %s failed", IPERF_TRAFFIC_TASK_NAME);
        free(s_iperf_ctrl.buffer);
        s_iperf_ctrl.buffer = NULL;
        return ESP_FAIL;
    }
    net_iperf_print_header(cfg);
    return ESP_OK;
}

esp_err_t iperf_stop(void)
{
    if (s_iperf_is_running) {
        s_iperf_ctrl.finish = true;
    }

    return ESP_OK;
}

/**
 * @brief Parameters needed to parse the command line
 *
 */
typedef struct getopt_env {
    char *optarg;    /*!< if the option accepts parameters, then optarg point to the option parameter*/
    int optind;      /*!< current index of argv*/
    int opterr;      /*!< non-zero enable error message output, while 0,no error message output*/
    int optopt;      /*!< contain unrecognized option character*/
    int __optpos;
} getopt_env_t;

int utils_getopt_init(getopt_env_t *env, int opterr)
{
    if (!env) {
        return -1;
    }
    env->optarg = NULL;
    env->optind = 1;
    env->opterr = opterr;
    env->optopt = 0;
    env->__optpos = 0;
    return 0;
}

int utils_getopt(getopt_env_t *env, int argc, char * const argv[], const char *optstring)
{
    int i;
    char c, d;
    char *optchar;

    if (!env) {
        return -1;
    }

    if (env->optind >= argc || !argv[env->optind])
        return -1;

    if (argv[env->optind][0] != '-') {
        if (optstring[0] == '-') {
            env->optarg = argv[env->optind++];
            return 1;
        }
        return -1;
    }

    if (!argv[env->optind][1])
        return -1;

    if (argv[env->optind][1] == '-' && !argv[env->optind][2])
        return env->optind++, -1;

    if (!env->__optpos) env->__optpos++;
    c = argv[env->optind][env->__optpos];
    optchar = argv[env->optind] + env->__optpos;
    env->__optpos += !!c;

    if (!argv[env->optind][env->__optpos]) {
        env->optind++;
        env->__optpos = 0;
    }

    if (optstring[0] == '-' || optstring[0] == '+')
        optstring++;

    i = 0;
    do d = optstring[i++]; while (d && d != c);

    if (d != c || c == ':') {
        env->optopt = c;
        if (optstring[0] != ':' && env->opterr)
            printf("%s: unrecognized option: %c"NEWLINE, argv[0], *optchar);
        return '?';
    }
    if (optstring[i] == ':') {
        env->optarg = 0;
        if (optstring[i+1] != ':' || env->__optpos) {
            env->optarg = argv[env->optind++] + env->__optpos;
            env->__optpos = 0;
        }
        if (env->optind > argc) {
            env->optopt = c;
            if (optstring[0] == ':') return ':';
            if (env->opterr) {
                printf("%s: option requires an argument: %c"NEWLINE, argv[0], *optchar);
            }
            return '?';
        }
    }
    return c;
}

static void iperf_cmd(int argc, char **argv)
{
    getopt_env_t opt_env;
    int opt;
    int o_c = 0, o_s = 0, o_u = 0, o_a = 0;
    int o_p = IPERF_DEFAULT_PORT, o_l = 0, o_i = IPERF_DEFAULT_INTERVAL, o_t = IPERF_DEFAULT_TIME, o_b = IPERF_DEFAULT_NO_BW_LIMIT, o_S = 0, o_n = 0;
    int o_d = 0;
    int o_P = IPERF_TRAFFIC_TASK_PRIORITY;
    uint32_t dst_addr = 0;

    iperf_cfg_t cfg;

    printf("argc: %d\r\n", argc);
    for (int j = 0; j < argc; j++) {
      printf("argv[%d]: %s\r\n", j, argv[j]);
    }

    utils_getopt_init(&opt_env, 0);
    while ((opt = utils_getopt(&opt_env, argc, argv, ":c:sup:l:i:t:b:S:n:P:ad")) != -1) {
        #define ARG_READ(v) v = atoi(opt_env.optarg)
        switch (opt) {
        case 'c':
            ++o_c;
            dst_addr = ipaddr_addr(opt_env.optarg);
            break;
        case 's': ++o_s; break;
        case 'u': ++o_u; break;
        case 'p': ARG_READ(o_p); break;
        case 'l': ARG_READ(o_l); break;
        case 'i': ARG_READ(o_i); break;
        case 't': ARG_READ(o_t); break;
        case 'b': ARG_READ(o_b); break;
        case 'S': ARG_READ(o_S); break;
        case 'n': ARG_READ(o_n); break;
        case 'P': ARG_READ(o_P); break;
        case 'd': ++o_d; break;
        case 'a': ++o_a; break;
        }
        #undef ARG_READ
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.type = IPERF_IP_TYPE_IPV4;

    if (o_a) {
        iperf_stop();
        return;
    }
    if (!((o_c && !o_s) || (!o_c && o_s))) {
        printf("client/server required" NL);
        return;
    }
    if (o_c) {
        cfg.destination_ip4 = dst_addr;
        cfg.flag |= IPERF_FLAG_CLIENT;
    } else {
        cfg.flag |= IPERF_FLAG_SERVER;
    }
    if (o_u) {
        cfg.flag |= IPERF_FLAG_UDP;
    } else {
        cfg.flag |= IPERF_FLAG_TCP;
    }

    if (o_c && !o_u && o_d) {
        cfg.flag |= IPERF_FLAG_DUAL;
    }

    cfg.len_buf = o_l;
    cfg.sport = o_p;
    cfg.dport = o_p;
    cfg.interval = o_i;
    cfg.time = o_t;
    if (cfg.time < cfg.interval) {
        cfg.time = cfg.interval;
    }
    cfg.bw_lim = o_b;
    cfg.tos = o_S;
    cfg.num_bytes = o_n * 1000 * 1000;
    if (cfg.bw_lim <= 0) {
        cfg.bw_lim = IPERF_DEFAULT_NO_BW_LIMIT;
    }
    cfg.traffic_task_priority = o_P;

    iperf_start(&cfg);
}

#define ML(s) s NL
#define IPERF_USAGE \
    ML("iperf") \
    ML(" -c server_addr: run in client mode") \
    ML(" -s: run in server mode") \
    ML(" -u: UDP") \
    ML(" -p port: specify port") \
    ML(" -l length: set read/write buffer size") \
    ML(" -i interval: seconds between bandwidth reports") \
    ML(" -t time: time in seconds to run") \
    ML(" -b bandwith: bandwidth to send in Mbps") \
    ML(" -S tos: TOS") \
    ML(" -n MB: number of MB to send/recv") \
    ML(" -P priority: traffic task priority") \
    ML(" -d: dual mode") \
    ML(" -a: abort running iperf") \

#if 0
static lwshell_cmd_t cmd_static_iperf[] = {
  {iperf_cmd, "iperf", IPERF_USAGE}
};

void lwshell_register_cmd_iperf(void)
{
  lwshell_register_static_cmds(cmd_static_iperf, sizeof(cmd_static_iperf)/sizeof(cmd_static_iperf[0]));
}
#endif
