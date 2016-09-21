#ifndef __LOG_H__
#define __LOG_H__
#define LOG_MAGIC "ipsetmagic"
int log_dmsg_is_valid(char *log);
int log_handle(char *log);
#endif
