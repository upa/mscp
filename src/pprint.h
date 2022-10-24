#ifndef _PPRINT_H_
#define _PPRINT_H_

/* progress print functions */

void pprint_set_level(int level);
void pprint(int level, const char *fmt, ...);

#define pprint1(fmt, ...) pprint(1, "\r\033[K" fmt, ##__VA_ARGS__)
#define pprint2(fmt, ...) pprint(2, "\r\033[K" fmt, ##__VA_ARGS__)
#define pprint3(fmt, ...) pprint(3, "\r\033[K" fmt, ##__VA_ARGS__)
#define pprint4(fmt, ...) pprint(4, "\r\033[K" fmt, ##__VA_ARGS__)

#endif /* _PPRRINT_H_ */
