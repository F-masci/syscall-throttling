MODULE_NAME := sct
OUT_DIR 	:= $(PWD)/out

HDISC_DIR 	:= hook/discover
HFTRACE_DIR := hook/ftrace

# Set to enable FTRACE hooking method
#
# 1 = Enable FTRACE hooking
# 0 = Enable DISCOVER hooking
ENABLE_FTRACE := 1

# Set to SPINLOCK_PROTECTED to use spinlocks as synchronization method
# Set to RCU_PROTECTED to use RCU as synchronization method (default)
#
SYNC_METHOD := RCU_PROTECTED

# DBG_FLAGS := dyndbg=+p
DBG_FLAGS   :=
# DBG_DEFINE  := -DDEBUG
DBG_DEFINE  :=

KDIR := /lib/modules/$(shell uname -r)/build

SIGN_FILE 	:= $(KDIR)/scripts/sign-file
MOK_PRIV 	:= $(PWD)/keys/MOK.priv
MOK_DER  	:= $(PWD)/keys/MOK.der

# --- SEZIONE KBUILD ---
ifneq ($(KERNELRELEASE),)
    obj-m := $(MODULE_NAME).o
    $(MODULE_NAME)-y := main.o ops.o monitor.o timer.o stats.o filter.o dev.o hook.o
	ccflags-y := -std=gnu11 $(DBG_DEFINE) -D$(SYNC_METHOD)

	ifeq ($(ENABLE_FTRACE), 1)
        $(MODULE_NAME)-y += $(HFTRACE_DIR)/fhook.o
        ccflags-y 		 += -DFTRACE_HOOKING -I$(src)/$(HFTRACE_DIR)
	else
		$(MODULE_NAME)-y += $(HDISC_DIR)/dhook.o $(HDISC_DIR)/disc.o $(HDISC_DIR)/sthack.o $(HDISC_DIR)/lib/vtpmo.o
		ccflags-y 		 += -DDISCOVER_HOOKING -I$(src)/$(HDISC_DIR) -I$(src)/$(HDISC_DIR)/lib
    endif

# --- SEZIONE USERSPACE ---
else
    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    SIGN_FILE := $(KDIR)/scripts/sign-file

all:

	@echo "=== Compile main module: $(MODULE_NAME) ==="
	$(MAKE) -C $(KDIR) M=$(PWD)

	@mkdir -p $(OUT_DIR)

	@echo "=== Moving compiled files to $(OUT_DIR) ==="
	@mv -f *.ko *.o *.mod.c *.mod modules.order Module.symvers $(OUT_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .module-common.o $(OUT_DIR)/ 2>/dev/null || true

	@rm -f $(HDISC_DIR)/*.o $(HDISC_DIR)/.*.cmd
	@rm -f $(HFTRACE_DIR)/*.o $(HFTRACE_DIR)/.*.cmd

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
	sudo insmod $(OUT_DIR)/$(MODULE_NAME).ko $(DBG_FLAGS)

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
	rm -f $(HDISC_DIR)/*.o $(HDISC_DIR)/.*.cmd
	rm -f $(HFTRACE_DIR)/*.o $(HFTRACE_DIR)/.*.cmd

	@echo "Clean completed."

endif
