#ifndef __CAPTURE_DEMO_H__
#define __CAPTURE_DEMO_H__


#ifndef CAPTURE_ALL
/* ip protocol */
#define CAPTURE_ALL   ((unsigned int)(~(0<<31)))
#define CAPTURE_TCP   ((unsigned int)(1<<0))
#define CAPTURE_UDP   ((unsigned int)(1<<1))
#define CAPTURE_ICMP  ((unsigned int)(1<<2))
#define CAPTURE_ARP  ((unsigned int)(1<<3))

#endif

#define log_info(fmt, arg...) printk("<6> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)

#define log_warn(fmt, arg...) printk("<4> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)
#define log_err(fmt, arg...) printk("<3> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)
#define log_debug(fmt, arg...) if(capture_debug) \
                                  printk("<1> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)  

#ifndef CIP1
#define CIP1(addr)  ((unsigned char *)&addr)[0]
#define CIP2(addr)  ((unsigned char *)&addr)[1]
#define CIP3(addr)  ((unsigned char *)&addr)[2]
#define CIP4(addr)  ((unsigned char *)&addr)[3]
#endif

#ifndef NMACQUAD
#define NMACQUAD(mac)  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
#endif

#ifndef NMAC1
#define NMAC1(mac)  mac[0]
#define NMAC2(mac)  mac[1]
#define NMAC3(mac)  mac[2]
#define NMAC4(mac)  mac[3]
#define NMAC5(mac)  mac[4]
#define NMAC6(mac)  mac[5]
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


#endif
