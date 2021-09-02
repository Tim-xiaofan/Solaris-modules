qotd_2:qotd_2.o
	/usr/ccs/bin/ld -r -o qotd_2 qotd_2.o
qotd_2.o:qotd_2.c
	gcc -Wall -Wno-missing-braces  -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -c qotd_2.c
clean:
	rm  -f qotd_2.o qotd_2
