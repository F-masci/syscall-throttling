#include "disc.h"
#include "sthack.h"

#include "dhook.h"
#include "../../sct.h"

/**
 * @brief Install a syscall hook using discover
 * 
 * @param syscall_idx Syscall number to hook
 * @param hook_addr Address of the hook function
 * @return unsigned long Original syscall address
 */
unsigned long install_syscall_dhook(scidx_t syscall_idx, unsigned long hook_addr) {
    
    unsigned long ** hacked_syscall_tbl = get_syscall_table_addr();
    unsigned long * original_syscall_addrs = get_original_syscall_addrs();

    // Basic safety check
    if (!hacked_syscall_tbl) {
        PR_ERROR("Syscall table not found\n");
        return (unsigned long) NULL;
    }

    begin_syscall_table_hack();
    PR_DEBUG("Syscall table hacking started for syscall %d\n", syscall_idx);

    // Save the original syscall address (done only once at startup)
	// original_syscall_addrs[syscall_idx] = (unsigned long)hacked_syscall_tbl[syscall_idx];

    // Install the hook
    hacked_syscall_tbl[syscall_idx] = (unsigned long *) hook_addr;

    end_syscall_table_hack();
    PR_DEBUG("Syscall table hacking ended for syscall %d\n", syscall_idx);

    PR_INFO("Hook installed on syscall %d.\n", syscall_idx);
    return original_syscall_addrs[syscall_idx];
}

/**
 * @brief Remove a syscall hook using discover
 * 
 * @param syscall_idx Syscall number to unhook
 * @return unsigned long Address of the removed hook
 */
unsigned long uninstall_syscall_dhook(int syscall_idx) {

    unsigned long hook_addr;

    unsigned long ** hacked_syscall_tbl = get_syscall_table_addr();
    unsigned long * original_syscall_addrs = get_original_syscall_addrs();

	// Basic safety check
    if (!hacked_syscall_tbl || !hacked_syscall_tbl[syscall_idx] || !original_syscall_addrs || !original_syscall_addrs[syscall_idx]) {
		PR_ERROR("Invalid state for syscall %d.\n", syscall_idx);
		return (unsigned long) NULL;
	}

    // Get the current hook address
	hook_addr = (unsigned long) hacked_syscall_tbl[syscall_idx];

    begin_syscall_table_hack();
    PR_DEBUG("Syscall table hacking started for syscall %d\n", syscall_idx);

    // Restore the original syscall address
    hacked_syscall_tbl[syscall_idx] = (unsigned long *) original_syscall_addrs[syscall_idx];

    end_syscall_table_hack();
    PR_DEBUG("Syscall table hacking ended for syscall %d\n", syscall_idx);
    
    PR_INFO("Hook removed from syscall %d.\n", syscall_idx);
	return hook_addr;
}