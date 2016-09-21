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
    unsigned long long timestamp;
    uint32_t port;
    char *str;
    int ret;

    if (log_dmsg_is_whitelist(log)) {
        printf("white list\n");
    } else if (log_dmsg_is_blacklist(log)) {
        /*
        4,1813,131759525162,-;ipsetmagic_blacklistIN= OUT=ens34 SRC=192.168.231.130 DST=115.239.210.27 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=16302 DF PROTO=TCP SPT=49900 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0
        */
        printf("black list\n");
        ret = sscanf(log, "%*u,%*u,%llu\n", &timestamp);
        if (1 != ret) {
            return -1;
        }
        printf("timestamp found %llu ", timestamp);
        str = strstr(log, "SRC=");
        if (NULL == str) {
            return -1;
        }
        printf("SRC found ");
        ret = sscanf(str, "SRC=%u.%u.%u.%u", &(ip_src[0]), &(ip_src[1]), &(ip_src[2]), &(ip_src[3]));
        if (4 != ret) {
            return -1;
        }
        printf("%u.%u.%u.%u, ", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
        str = strstr(log, "DST=");
        if (NULL == str) {
            return -1;
        }
        printf("DST found ");
        ret = sscanf(str, "DST=%u.%u.%u.%u", &(ip_dst[0]), &(ip_dst[1]), &(ip_dst[2]), &(ip_dst[3]));
        if (4 != ret) {
            return -1;
        }
        printf("%u.%u.%u.%u, ", ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);
        str = strstr(log, "DPT=");
        if (NULL == str) {
            return -1;
        }
        printf("DPT found ");
        ret = sscanf(str, "DPT=%u", &port);
        if (1 != ret) {
            return -1;
        }
        printf("%u\n", port);
    }
    return 0;
}
