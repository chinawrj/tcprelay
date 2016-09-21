#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

int log_dmsg_is_valid(char *log)
{
    if (strstr(log, LOG_MAGIC)) {
        return 1;
    } else {
        return 0;
    }
}

static int log_dmsg_is_blacklist(char *log)
{
    /*
    4,1813,131759525162,-;ipsetmagic_blacklistIN= OUT=ens34 SRC=192.168.231.130 DST=115.239.210.27 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=16302 DF PROTO=TCP SPT=49900 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0
    */
    if (strstr(log, "ipsetmagic_blacklist")) {
        return 1;
    } else {
        return 0;
    }
}

static int log_dmsg_is_whitelist(char *log)
{
    if (strstr(log, "ipsetmagic_whitelist")) {
        return 1;
    } else {
        return 0;
    }
}

int log_handle(char *log)
{
    uint32_t ip_src[4], ip_dst[4];
    uint32_t timestamp;
    uint32_t port;
    uint32_t count;
    char *str;
    int ret;

    if (log_dmsg_is_whitelist(log)) {
        printf("white list\n");
    } else if (log_dmsg_is_blacklist(log)) {
        printf("black list\n");
    }
    return 0;
}
