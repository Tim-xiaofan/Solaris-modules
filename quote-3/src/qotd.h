#ifndef _SYS_QOTD_H
#define _SYS_QOTD_H

#define QOTDIOC         ('q' << 24 | 't' << 16 | 'd' << 8)

#define QOTDIOCGSZ      (QOTDIOC | 1)   /* Get quote buffer size */
#define QOTDIOCSSZ      (QOTDIOC | 2)   /* Set new quote buffer size */
#define QOTDIOCDISCARD  (QOTDIOC | 3)   /* Discard quotes and reset */
#define QOTDIOCSPID	(QOTDIOC | 4)	
#define QOTDIOCGPID	(QOTDIOC | 5)		
#define QOTDIOCSFD	(QOTDIOC | 6)		
#define QOTDIOCGFD	(QOTDIOC | 7)		
#define QOTDIOCSIP	(QOTDIOC | 8)		
#define QOTDIOCGIP	(QOTDIOC | 9)		
#define QOTDIOCSPORT	(QOTDIOC | 10)		
#define QOTDIOCGPORT	(QOTDIOC | 11)		

#endif /* _SYS_QOTD_H */
