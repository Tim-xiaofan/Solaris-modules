/* simple kernel module: qotd_2
 * Licensed under GPLv2 or later
 * */

#ifndef _QOTD_2_IOCTL_H
#define _QOTD_2_IOCTL_H

#define IOC_MAGIC 's'
#define IOCSPID		0x1 
#define IOCGPID		0x2 
#define IOCSFD		0x4
#define IOCGFD		0x8      
#define IOCSIP		0x10      
#define IOCGIP		0x20      
#define IOCSPORT	0x40    
#define IOCGPORT	0x50    

#endif
