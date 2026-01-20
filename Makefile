MODULE_NAME := sct
OUT_DIR := $(PWD)/out

DISCOVER_MODULE := the_usctm
DISCOVER_DIR := $(PWD)/discover

KDIR := /lib/modules/$(shell uname -r)/build

SIGN_FILE := $(KDIR)/scripts/sign-file
MOK_PRIV := $(PWD)/keys/MOK.priv
MOK_DER  := $(PWD)/keys/MOK.der

# --- SEZIONE KBUILD ---
ifneq ($(KERNELRELEASE),)
    obj-m := $(MODULE_NAME).o
    $(MODULE_NAME)-y := main.o ops.o probes.o ftrace.o monitor.o discover.o timer.o stats.o
	ccflags-y := -std=gnu11

# --- SEZIONE USERSPACE ---
else
    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    SIGN_FILE := $(KDIR)/scripts/sign-file

all:

	@echo "=== Check Dependency Symbols ==="
	@if [ ! -f "$(DISCOVER_DIR)/Module.symvers" ]; then \
		echo "ERROR: $(DISCOVER_DIR)/Module.symvers not found."; \
		echo "You must manually compile the module inside 'discover/' before compiling this one!"; \
		exit 1; \
	fi
	@echo "Dependency symbols found."

	@echo "=== Compile main module: $(MODULE_NAME) ==="
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(DISCOVER_DIR)/Module.symvers modules

	@mkdir -p $(OUT_DIR)

	@echo "=== Moving compiled files to $(OUT_DIR) ==="
	@mv -f *.ko *.o *.mod.c *.mod modules.order Module.symvers $(OUT_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .module-common.o $(OUT_DIR)/ 2>/dev/null || true

	@mv -f $(DISCOVER_DIR)/*.ko $(OUT_DIR)/ 2>/dev/null || true
	@mv -f $(DISCOVER_DIR)/Module.symvers $(OUT_DIR)/$(DISCOVER_NAME)_Module.symvers 2>/dev/null || true

	@# Automatic WSL detection and BTF fix
	@if uname -r | grep -q -i "microsoft"; then \
		echo "WSL environment detected: Removing .BTF section for compatibility..."; \
		objcopy --remove-section=.BTF $(OUT_DIR)/$(MODULE_NAME).ko; \
	fi

	@echo "=== Checking MOK keys for signing ==="
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
	@./make_syst_h.sh
	
	@echo "Build environment ready."

load:
	@echo "=== Loading main module: $(MODULE_NAME) ==="
	sudo insmod $(OUT_DIR)/$(MODULE_NAME).ko

	@echo "Modules loaded successfully."

unload:
	@echo "=== Unloading main module: $(MODULE_NAME) ==="
	@if lsmod | grep -q "^$(MODULE_NAME)"; then \
        echo "Unloading $(MODULE_NAME)..."; \
        sudo rmmod $(MODULE_NAME); \
    else \
        echo "$(MODULE_NAME) not loaded."; \
    fi

	@echo "Modules unloaded successfully.";

clean:
	@echo "=== Cleaning main module... ===";
	$(MAKE) -C $(KDIR) M=$(OUT_DIR) src=$(PWD) clean
    
	rm -rf $(OUT_DIR)

endif
