/* nl-oppscan.c
 *
 * Author: Federico Cifuentes-Urtubey <fc8@illinois.edu>
 * 
 * Compile: gcc nl-oppscan.c -o nl-oppscan -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
 * Usage:   ./nl-oppscan <interface>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define BUF_SIZE 4096
#define NL80211_ATTR_MAC 6

// Helper function to send a probe request frame
static int send_probe_request(int sock, const char *ifname);

int main(int argc, char **argv)
{
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl_msg_hdr;
    struct nlattr *nlattr_msg;
    int sock;
    char buf[BUF_SIZE];

    // Create netlink socket
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    // Bind socket
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = 0;
    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(sock);
        return EXIT_FAILURE;
    }

    // Allocate netlink message header
    nlh = (struct nlmsghdr *)buf;
    memset(nlh, 0, NLMSG_LENGTH(GENL_HDRLEN));

    // Fill netlink message header
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();

    // Allocate generic netlink message header
    genl_msg_hdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
    memset(genl_msg_hdr, 0, GENL_HDRLEN);

    // Fill generic netlink message header
    genl_msg_hdr->cmd = CTRL_CMD_GETFAMILY;
    genl_msg_hdr->version = 0x1;

    // Allocate netlink attribute message
    nlattr_msg = (struct nlattr *)GENLMSG_DATA(genl_msg_hdr);
    nlattr_msg->nla_type = CTRL_ATTR_FAMILY_NAME;
    nlattr_msg->nla_len = strlen(NL80211_GEN_NAME) + 1 + NLA_HDRLEN;
    strcpy(NLA_DATA(nlattr_msg), NL80211_GEN_NAME);

    // Add netlink attribute message to netlink message header
    nlh->nlmsg_len += NLMSG_ALIGN(nlattr_msg->nla_len);

    // Send netlink message to kernel
    if (send(sock, nlh, nlh->nlmsg_len, 0) < 0)
    {
        perror("send");
        close(sock);
        return EXIT_FAILURE;
    }

    // Receive netlink message from kernel
    while (1)
    {
        ssize_t len;

        len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv");
            close(sock);
            return EXIT_FAILURE;
        }

        for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len))
        {
            if (nlh->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
                if (nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
                    fprintf(stderr, "error: %s\n", strerror(-err->error));
                close(sock);
                return EXIT_FAILURE;
            } 
            else if (nlh->nlmsg_type == NLMSG_DONE)
            {
                break;
            }
            else if (nlh->nlmsg_type == NLMSG_NOOP)
            {
                // Ignore noop
            } 
            else
            {
                genl_msg_hdr = (struct genlmsghdr *)NLMSG_DATA(nlh);

                if (genl_msg_hdr->cmd == NL80211_CMD_NEW_SCAN_RESULTS)
                {
                    nlattr_msg = (struct nlattr *)GENLMSG_DATA(genl_msg_hdr);
                    
                    while (NL80211_ATTR_MAC != nlattr_msg->nla_type)
                    {
                        nlattr_msg = (struct nlattr *)((void *)nlattr_msg + NLA_ALIGN(nlattr_msg->nla_len));
                        if ((void *)nlattr_msg >= (void *)nlh + nlh->nlmsg_len) 
                        {
                            break;
                        }
                    }

                    if (NL80211_ATTR_MAC == nlattr_msg->nla_type)
                    {
                        // Get MAC address
                        char mac[18];
                        unsigned char *ptr = (unsigned char *)nla_data(nlattr_msg);

                        sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
                            // ((unsigned char *)nla_data(nlattr_msg))[0],
                            // ((unsigned char *)nla_data(nlattr_msg))[1],
                            // ((unsigned char *)nla_data(nlattr_msg))[2],
                            // ((unsigned char *)nla_data(nlattr_msg))[3],
                            // ((unsigned char *)nla_data(nlattr_msg))[4],
                            // ((unsigned char *)nla_data(nlattr_msg))[5]);

                        printf("Received probe request from %s\n", mac);

                        // Send probe request after 100ms
                        usleep(100000);
                        send_probe_request(sock, argv[1]);
                    }
                }
            }
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}

static int send_probe_request(int sock, const char *ifname)
{
    struct nl_msg *msg;
    int ret;
    
    msg = nlmsg_alloc();
    if (!msg)
    {
        fprintf(stderr, "error: nlmsg_alloc failed\n");
        return -ENOMEM;
    }

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, 0, 0, NLM_F_REQUEST, NL80211_CMD_TRIGGER_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname));
    nla_put(msg, NL80211_ATTR_SCAN_SSIDS, 0, NULL);

    ret = nl_send_auto_complete(sock, msg);
    if (ret < 0)
    {
        fprintf(stderr, "error: nl_send_auto_complete failed: %s\n", nl_geterror(ret));
        return ret;
    }

    nlmsg_free(msg);
    return 0;

nla_put_failure:
    nlmsg_free(msg);
    fprintf(stderr, "error: nla_put_failure\n");
    return -ENOMEM;
}