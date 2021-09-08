qotd_3:qotd_3.o sock.o
	/usr/ccs/bin/ld -r -o qotd_3  qotd_3.o sock.o
qotd_3.o:qotd_3.c qotd.h
	gcc -Wall -Wno-missing-braces  -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -c qotd_3.c
sock.o : sock.c sock.h
	gcc -Wall -Wno-missing-braces  -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -c sock.c
clean:
	rm  -f *.o qotd_3
