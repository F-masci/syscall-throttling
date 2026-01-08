MODULE_NAME := sct
OUT_DIR := $(PWD)/out

KDIR := /lib/modules/$(shell uname -r)/build

SIGN_FILE := $(KDIR)/scripts/sign-file
MOK_PRIV := $(PWD)/keys/MOK.priv
MOK_DER  := $(PWD)/keys/MOK.der

# --- SEZIONE KBUILD ---
ifneq ($(KERNELRELEASE),)
    obj-m := $(MODULE_NAME).o
    $(MODULE_NAME)-y := main.o ops.o
	ccflags-y := -std=gnu11

# --- SEZIONE USERSPACE ---
else
    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    SIGN_FILE := $(KDIR)/scripts/sign-file

all:
	@echo "Compilazione del modulo in corso..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

	@mkdir -p $(OUT_DIR)

	@echo "Spostamento dei file compilati in $(OUT_DIR)..."
	@mv -f *.ko *.o *.mod.c *.mod modules.order Module.symvers $(OUT_DIR)/ 2>/dev/null || true
	@mv -f .*.cmd .module-common.o $(OUT_DIR)/ 2>/dev/null || true

	@# Rilevamento automatico WSL e fix BTF
	@if uname -r | grep -q -i "microsoft"; then \
		echo "Ambiente WSL rilevato: Rimozione sezione .BTF per compatibilità..."; \
		objcopy --remove-section=.BTF $(OUT_DIR)/$(MODULE_NAME).ko; \
	fi

	@echo "Verifica della chiave MOK..."
	@if [ -f "$(MOK_PRIV)" ]; then \
		echo "Firma del modulo in corso..."; \
		$(SIGN_FILE) sha256 $(MOK_PRIV) $(MOK_DER) $(OUT_DIR)/$(MODULE_NAME).ko; \
	else \
		echo "ATTENZIONE: Chiave MOK.priv non trovata. Il modulo non è firmato!"; \
	fi
	
	@echo "Build completata. I file sono in: $(OUT_DIR)"

setup:
	@echo "Impostazione dell'ambiente di build..."
	# sudo apt-get update
	# sudo apt-get install -y build-essential linux-headers-$(shell uname -r) bc flex bison libelf-dev dwarves

	@# Rilevamento automatico WSL e fix BTF
	@if uname -r | grep -q -i "microsoft"; then \
		echo "Ambiente WSL rilevato: Impostazione link simbolico per build kernel..."; \
		sudo ln -snf /usr/src/Linux-Kernel-$(shell uname -r) /lib/modules/$(shell uname -r)/build; \
	fi

	@echo "Ambiente di build pronto."

load:
	@echo "Caricamento del modulo..."
	sudo insmod $(OUT_DIR)/$(MODULE_NAME).ko
	@echo "Modulo caricato."

unload:
	@echo "Scaricamento del modulo..."
	sudo rmmod $(MODULE_NAME)
	@echo "Modulo scaricato."

clean:
	$(MAKE) -C $(KDIR) M=$(OUT_DIR) src=$(PWD) clean
	rm -rf $(OUT_DIR)

endif
