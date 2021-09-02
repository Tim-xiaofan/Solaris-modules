foomod:foomod.o
	/usr/ccs/bin/ld -r -o foomod foomod.o
foomod.o:foomod.c
	gcc -D_KERNEL -m64 -mcmodel=kernel -mno-red-zone -ffreestanding -nodefaultlibs -c foomod.c
clean:
	rm  -f foomod.o foomod
