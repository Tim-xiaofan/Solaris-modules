dummy:dummy.o
	/usr/ccs/bin/ld -r -o dummy dummy.o
dummy.o:dummy.c
	gcc -Wall -Wno-missing-braces  -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -c dummy.c
clean:
	rm  -f dummy.o dummy
