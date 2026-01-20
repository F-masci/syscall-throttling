#include "disc.h"
#include "sthack.h"

#include "dhook.h"
#include "../../sct.h"

/**
 * @brief Install a syscall hook
 * 
 * @param syscall_nr Syscall number to hook
 * @param hook_addr Address of the hook function
 * @return unsigned long Original syscall address
 */
unsigned long install_syscall_dhook(scidx_t syscall_nr, unsigned long hook_addr) {
    
    unsigned long ** hacked_syscall_tbl = get_syscall_table_addr();
    unsigned long * original_syscall_addrs = get_original_syscall_addrs();

    // Basic safety check
    if (!hacked_syscall_tbl) {
        PR_ERROR("Syscall table not found\n");
        return (unsigned long) NULL;
    }

    begin_syscall_table_hack();

    // Save the original syscall address (done only once at startup)
	// original_syscall_addrs[syscall_nr] = (unsigned long)hacked_syscall_tbl[syscall_nr];

    // Install the hook
    hacked_syscall_tbl[syscall_nr] = (unsigned long *) hook_addr;

    end_syscall_table_hack();

    PR_INFO("Hook installed on syscall %d.\n", syscall_nr);
    return original_syscall_addrs[syscall_nr];
}

/**
 * @brief Remove a syscall hook
 * 
 * @param syscall_nr Syscall number to unhook
 * @return unsigned long Address of the removed hook
 */
unsigned long uninstall_syscall_dhook(int syscall_nr) {

    unsigned long hook_addr;

    unsigned long ** hacked_syscall_tbl = get_syscall_table_addr();
    unsigned long * original_syscall_addrs = get_original_syscall_addrs();

	// Basic safety check
    if (!hacked_syscall_tbl || !hacked_syscall_tbl[syscall_nr] || !original_syscall_addrs || !original_syscall_addrs[syscall_nr]) {
		PR_ERROR("Cannot uninstall hook for syscall %d.\n", syscall_nr);
		return (unsigned long) NULL;
	}

    // Get the current hook address
	hook_addr = (unsigned long) hacked_syscall_tbl[syscall_nr];

    begin_syscall_table_hack();

    // Restore the original syscall address
    hacked_syscall_tbl[syscall_nr] = (unsigned long *) original_syscall_addrs[syscall_nr];

    end_syscall_table_hack();
    
    PR_INFO("Hook removed from syscall %d.\n", syscall_nr);
	return hook_addr;
}