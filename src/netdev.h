#ifndef NETDEV_H
#define NETDEV_H

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct netdev {
    char name[IFNAMSIZ];
    int index;
    char mac[18];
    char ip[INET_ADDRSTRLEN];
    struct netdev *next;
};

int bind_socket_to_netdev(int sock, const char *devname);
const char *get_netdev_by_index(int index);
int get_netdev_count(void);
void free_netdev_list(void);
// 新增：支持指定网卡名列表
int get_netdev_list(const char **devnames, int devcount);

#endif /* NETDEV_H */ 