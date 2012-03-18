obj-m += sys_xcrypt.o

xcryptModDir = :$(PWD)

all:
	cc xcrypt.c -Wall -Werror -o xcipher -L/usr/lib -lssl -lcrypto 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm xcipher
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
