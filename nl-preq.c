/* nl-preq.c
 * A program to transmit a probe request with libnl.
 *
 * Author: Federico Cifuentes-Urtubey <fc8@illinois.edu>
 *
 * Compile: gcc nl-preq.c -o nlpreq -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
 * Usage:   sudo ./nlpreq
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/utils.h>

#define SSID_NAME ""
#define CHANNEL_NUMBER 11

int main(int argc, char *argv[])
{
    struct nl_sock *socket;
    struct nl_msg *msg;
    int if_index, err;
    struct nlattr *ssids, *freqs;
    int ssids_len = strlen(SSID_NAME);
    int freqs_len = sizeof(uint32_t);

    socket = nl_socket_alloc();
    if (!socket) {
        printf("Failed to allocate netlink socket.\n");
        return -1;
    }

    if (genl_connect(socket) < 0) {
        printf("Failed to connect to generic netlink.\n");
        nl_socket_free(socket);
        return -1;
    }

    int nl80211_id = genl_ctrl_resolve(socket, "nl80211");

    nl_socket_set_buffer_size(socket, 8192, 8192);

    if_index = if_nametoindex("wlan0");
    if (!if_index) {
        printf("Invalid interface name.\n");
        nl_socket_free(socket);
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        printf("Failed to allocate netlink message.\n");
        nl_socket_free(socket);
        return -1;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_id, 0, NLM_F_REQUEST, NL80211_CMD_TRIGGER_SCAN, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);

    ssids = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
    nla_put(msg, 1, ssids_len, SSID_NAME);
    nla_nest_end(msg, ssids);

    freqs = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
    nla_put_u32(msg, NL80211_ATTR_SCAN_FREQUENCIES, 2407 + CHANNEL_NUMBER * 5);
    nla_nest_end(msg, freqs);

    err = nl_send_auto(socket, msg);
    if (err < 0) {
        printf("Failed to send netlink message: %s\n", nl_geterror(err));
        nl_socket_free(socket);
        return -1;
    }

    nl_recvmsgs_default(socket);

    printf("Probe request sent.\n");

    nl_socket_free(socket);
    return 0;
}
