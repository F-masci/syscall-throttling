obj-m += the_usctm.o
the_usctm-objs += usctm.o ./lib/vtpmo.o

all:
	@echo "=== Compiling the_usctm module... ==="
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

	@# Automatic WSL detection and BTF fix
	@if uname -r | grep -q -i "microsoft"; then \
		echo "WSL environment detected: Removing .BTF section for compatibility..."; \
		objcopy --remove-section=.BTF the_usctm.ko; \
	fi

load:
	@echo "=== Loading the_usctm module... ==="
	sudo insmod the_usctm.ko

unload:
	@echo "=== Unloading the_usctm module... ==="
	sudo rmmod the_usctm

clean:
	@echo "=== Cleaning discover module... ==="
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
