#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <errno.h>
#include <print.h>
#include "netdev.h"

struct netdev *netdev_list = NULL;

// 支持指定网卡名列表
int get_netdev_list(const char **devnames, int devcount)
{
    struct ifconf ifc;
    struct ifreq *ifr;
    char buf[1024];
    int sock, i, n;
    struct netdev *dev, *prev = NULL;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        pr_err("socket: %s", strerror(errno));
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
        pr_err("ioctl: %s", strerror(errno));
        close(sock);
        return -1;
    }

    ifr = ifc.ifc_req;
    n = ifc.ifc_len / sizeof(struct ifreq);
    pr_debug("Found %d network interfaces", n);

    for (i = 0; i < n; i++) {
        struct ifreq *item = &ifr[i];
        int use = 1;
        // 跳过lo
        if (strcmp(item->ifr_name, "lo") == 0)
            continue;
        // 如果指定了网卡名，只处理指定的
        if (devnames && devcount > 0) {
            use = 0;
            for (int j = 0; j < devcount; ++j) {
                if (strcmp(item->ifr_name, devnames[j]) == 0) {
                    use = 1;
                    break;
                }
            }
        }
        if (!use)
            continue;

        struct netdev *dev = malloc(sizeof(struct netdev));
        if (!dev) {
            pr_err("malloc: %s", strerror(errno));
            close(sock);
            return -1;
        }

        strncpy(dev->name, item->ifr_name, IFNAMSIZ);
        dev->index = if_nametoindex(item->ifr_name);
        dev->next = NULL;
        // 获取MAC
        struct ifreq ifr_mac;
        memset(&ifr_mac, 0, sizeof(ifr_mac));
        strncpy(ifr_mac.ifr_name, item->ifr_name, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr_mac) == 0) {
            unsigned char *mac = (unsigned char *)ifr_mac.ifr_hwaddr.sa_data;
            snprintf(dev->mac, sizeof(dev->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            strcpy(dev->mac, "N/A");
        }
        // 获取IPv4
        struct ifreq ifr_ip;
        memset(&ifr_ip, 0, sizeof(ifr_ip));
        strncpy(ifr_ip.ifr_name, item->ifr_name, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFADDR, &ifr_ip) == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
            strncpy(dev->ip, inet_ntoa(sin->sin_addr), sizeof(dev->ip));
            dev->ip[sizeof(dev->ip)-1] = '\0';
        } else {
            strcpy(dev->ip, "N/A");
        }
        pr_notice("NIC: %s, MAC: %s, IP: %s", dev->name, dev->mac, dev->ip);

        if (!netdev_list) {
            netdev_list = dev;
        } else {
            struct netdev *prev = netdev_list;
            while (prev->next) prev = prev->next;
            prev->next = dev;
        }
    }

    close(sock);
    return 0;
}

void free_netdev_list(void)
{
    struct netdev *dev, *next;

    for (dev = netdev_list; dev; dev = next) {
        next = dev->next;
        free(dev);
    }
    netdev_list = NULL;
}

int bind_socket_to_netdev(int sock, const char *devname)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
    pr_debug("Binding socket to network device: %s", devname);

    // 1. SO_BINDTODEVICE
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        pr_err("setsockopt: %s", strerror(errno));
        return -1;
    }
    pr_debug("Successfully bound socket to network device: %s", devname);

    // 2. 获取设备 IP 并 bind
    struct ifreq ifr_ip;
    memset(&ifr_ip, 0, sizeof(ifr_ip));
    strncpy(ifr_ip.ifr_name, devname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr_ip) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
        pr_notice("SIOCGIFADDR for %s got IP: %s", devname, inet_ntoa(sin->sin_addr));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr = sin->sin_addr;
        addr.sin_port = 0;
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            pr_err("bind to ip %s failed: %s", inet_ntoa(sin->sin_addr), strerror(errno));
        } else {
            struct sockaddr_in check_addr;
            socklen_t check_len = sizeof(check_addr);
            if (getsockname(sock, (struct sockaddr *)&check_addr, &check_len) == 0) {
                pr_notice("After bind, getsockname IP: %s", inet_ntoa(check_addr.sin_addr));
            } else {
                pr_err("getsockname after bind failed: %s", strerror(errno));
            }
            pr_notice("Successfully bound socket to %s IP: %s", devname, inet_ntoa(sin->sin_addr));
        }
    } else {
        pr_err("ioctl SIOCGIFADDR failed for %s: %s", devname, strerror(errno));
    }

    return 0;
}

static struct netdev *get_netdev_by_position(int position)
{
    struct netdev *dev;
    int count = get_netdev_count();
    int actual_pos;
    int current = 0;

    if (count <= 0)
        return NULL;

    actual_pos = position % count;

    for (dev = netdev_list; dev; dev = dev->next) {
        if (current == actual_pos)
            return dev;
        current++;
    }

    return NULL;
}

const char *get_netdev_by_index(int index)
{
    struct netdev *dev;

    if (!netdev_list && get_netdev_list(NULL, 0) < 0)
        return NULL;

    dev = get_netdev_by_position(index);
    if (dev) {
        pr_notice("Mapped thread index %d to network device: %s", index, dev->name);
        return dev->name;
    }

    pr_notice("Failed to map thread index %d to any network device", index);
    return NULL;
}

int get_netdev_count(void)
{
    struct netdev *dev;
    int count = 0;

    if (!netdev_list && get_netdev_list(NULL, 0) < 0)
        return -1;

    for (dev = netdev_list; dev; dev = dev->next)
        count++;

    return count;
} 