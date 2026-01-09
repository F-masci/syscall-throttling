MODULE_NAME := sct
OUT_DIR := $(PWD)/out

KDIR := /lib/modules/$(shell uname -r)/build

SIGN_FILE := $(KDIR)/scripts/sign-file
MOK_PRIV := $(PWD)/keys/MOK.priv
MOK_DER  := $(PWD)/keys/MOK.der

# --- SEZIONE KBUILD ---
ifneq ($(KERNELRELEASE),)
    obj-m := $(MODULE_NAME).o
    $(MODULE_NAME)-y := main.o ops.o probes.o
	ccflags-y := -std=gnu11

# --- SEZIONE USERSPACE ---
else
    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    SIGN_FILE := $(KDIR)/scripts/sign-file

all:
	@echo "Module compilation in progress..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

	@mkdir -p $(OUT_DIR)

	@echo "Moving compiled files to $(OUT_DIR)..."
	@mv -f *.ko *.o *.mod.c *.mod modules.order Module.symvers $(OUT_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .module-common.o $(OUT_DIR)/ 2>/dev/null || true

	@# Automatic WSL detection and BTF fix
	@if uname -r | grep -q -i "microsoft"; then \
		echo "WSL environment detected: Removing .BTF section for compatibility..."; \
		objcopy --remove-section=.BTF $(OUT_DIR)/$(MODULE_NAME).ko; \
	fi

	@echo "Checking MOK key..."
	@if [ -f "$(MOK_PRIV)" ]; then \
		echo "Signing module..."; \
		$(SIGN_FILE) sha256 $(MOK_PRIV) $(MOK_DER) $(OUT_DIR)/$(MODULE_NAME).ko; \
	else \
		echo "WARNING: MOK.priv key not found. Module not signed!"; \
	fi

	@echo "Build completed. Files are in: $(OUT_DIR)"

setup:
	@echo "Setting up build environment..."
	# sudo apt-get update
	# sudo apt-get install -y build-essential linux-headers-$(shell uname -r) bc flex bison libelf-dev dwarves

	@# Automatic WSL detection and BTF fix
	@if uname -r | grep -q -i "microsoft"; then \
		echo "WSL environment detected: Setting up symlink for kernel build..."; \
		sudo ln -snf /usr/src/Linux-Kernel-$(shell uname -r) /lib/modules/$(shell uname -r)/build; \
	fi

	@# Setup of syscall names header
	@echo "Generating syscall names header..."
	@./gen_syscalls_table.sh
	
	@echo "Build environment ready."

load:
	@echo "Loading module..."
	sudo insmod $(OUT_DIR)/$(MODULE_NAME).ko
	@echo "Module loaded."

unload:
	@echo "Unloading module..."
	sudo rmmod $(MODULE_NAME)
	@echo "Module unloaded."

clean:
	$(MAKE) -C $(KDIR) M=$(OUT_DIR) src=$(PWD) clean
	rm -rf $(OUT_DIR)

endif
