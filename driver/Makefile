# Out-of-tree build:  make            (against the running kernel)
#                     make KDIR=/path/to/kernel/build
obj-m := oti2208_net.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
