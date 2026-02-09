# Specfiche del Progetto

This specification is related to a Linux Kernel Module (LKM) implementing a system call throttling mechanism. The LKM should offer a device driver for supporting the registration/deregistration of:

* program names (executable names)
* user IDs
* syscall numbers (according to x86-64 specification)

Such registration can be supported via the `ioctl(...)` system call. The registered syscall numbers are used to indicate that the corresponding systen calls can be critical for various aspects, like scalability, performance or security.
Each time one of the registered syscall is invoked by a program that is registered by the device driver or by a user (effective user-ID) that is registered by the device driver, the real execution of the system call needs to be controlled by a monitor offered by the LKM.

In particular, the LKM monitor can be configured to indicate what is the maximum number MAX of registered syscalls that can be actually invoked in a wall-clock-time window of 1 second by the registered program-names/user-IDs. If the actual volume of invocations per wall-clock-time unit exceeds MAX, then the invoking threads need to be temporarily blocked, thus preventing their actual syscall invocation.

The syscalls managed by the LKM can be of whathever nature. Hence they can be either blocking or non-blocking.

The device driver also needs to offer the possibility to verify at each time instant what are the registered program names, user-IDs and syscall numbers. Also, the update of such information can be only carried out by a thread which is running with effective user-ID set to the value 0 (root).

Also, the device driver needs to support the possibility to turn the syscall monitor off/on along time. If it is turned off, no limit on the frequencey of registered syscalls ivocations per wall-clock-time unit gets applied. Additionally, on the basis of the selected value for MAX, the device driver should also provide data related to:

* The peak delay for the actual execution of an invoked system call, and the corresponding program-name and user-ID
* The average and peak numbers of threads that had to be blocked

It is expected that the user level code for configuring the LKM monitor, and for testing the correct behavior of the developed LKM software is delivered as part of the project.
