#include <linux/errno.h>
#include <linux/preempt.h>
#include <asm/special_insns.h>
#include <asm/processor.h>

#include "sthack.h"

static unsigned long cr0, cr4;

static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void){
    write_cr0_forced(cr0);
}

static inline void unprotect_memory(void){
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}

static inline void write_cr4_forced(unsigned long val){
    unsigned long __force_order;
    asm volatile("mov %0, %%cr4" : "+r"(val), "+m"(__force_order));
}

static inline void conditional_cet_disable(void){
#ifdef X86_CR4_CET
    if (cr4 & X86_CR4_CET)
            write_cr4_forced(cr4 & ~X86_CR4_CET);
#endif
}

static inline void conditional_cet_enable(void){
#ifdef X86_CR4_CET
    if (cr4 & X86_CR4_CET)
            write_cr4_forced(cr4);
#endif
}

inline void begin_syscall_table_hack(void){
    preempt_disable();
    cr0 = read_cr0();
    cr4 = native_read_cr4();
    conditional_cet_disable();
    unprotect_memory();
}

inline void end_syscall_table_hack(void){
    protect_memory();
    conditional_cet_enable();
    preempt_enable();
}