# svc_stalker

![alt text](https://github.com/jsherman212/svc_stalker/blob/master/mini_strace.png)

<sup>*Output from intercepting some system calls/Mach traps for the App Store from
example/mini_strace.c*</sup>

**Currently working on call interception upon return and proper locking in this branch**

svc_stalker is a pongoOS module which modifies XNU to call `exception_triage`
on a supervisor call exception, sending a Mach exception message to userland
exception ports.

When `catch_mach_exception_raise` is called, the PID of the process which made
the call is placed in `code[0]`. `code[1]` will either be `BEFORE_CALL (0)`
or `CALL_COMPLETED (1)`. `BEFORE_CALL` means the call has not happened yet.
`CALL_COMPLETED` means the call has completed, but control hasn't been returned
back to the process which made it. You can find the call number in the lower
32 bits of `x16` inside the saved state of the `thread` parameter. `exception`
will hold either `EXC_SYSCALL` or `EXC_MACH_SYSCALL`, depending on what was
intercepted.

For both `BEFORE_CALL` and `CALL_COMPLETED`, you're free to view/modify
registers in your exception handler before giving control back to the kernel.

svc_stalker adds a new sysctl, `kern.svc_stalker_ctl_callnum`. This allows you
to figure out which system call was patched to svc_stalker_ctl:

```
size_t oldlen = sizeof(long);
long SYS_svc_stalker_ctl = 0;
sysctlbyname("kern.svc_stalker_ctl_callnum", &SYS_svc_stalker_ctl, &oldlen, NULL, 0);
```

Requires `libusb`: `brew install libusb`

Requires `perl`: `brew install perl`

## Building
Run `make` inside the top level directory. It'll automatically build the loader
and the `svc_stalker` module.

## Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

In the same directory you built the loader and the `svc_stalker` module,
do `loader/loader module/svc_stalker`. `svc_stalker` will patch the kernel and
in a few seconds XNU will boot.

## Known Issues
No iOS 14 support because pongoOS modules on checkra1n 11 are broken.

Sometimes a couple of my phones would get stuck at "Booting" after checkra1n's KPF
runs. I have yet to figure out what causes this, but if it happens, try again.
Also, if the device hangs after `bootx`, try again.

## svc_stalker_ctl
svc_stalker will patch the first `_enosys` system call in `_sysent` 
to instead point to a custom system call, `svc_stalker_ctl`.
In my experience, the system call that ends up being patched is #8. In
case it isn't, the module prints the patched system call number to the
device's framebuffer. You can also use `sysctlbyname` to query for it
(see above).

`svc_stalker_ctl` is your way of managing system call/Mach trap interception
for different processes. It takes four arguments, `pid`, `flavor`, `arg2`,
and `arg3`, respectively. `pid` is obviously the process you wish to interact
with. `flavor` is either `PID_MANAGE` (`0`) or `CALL_LIST_MANAGE` (`1`).

For `PID_MANAGE`, `arg2` controls whether or not calls are
intercepted for the `pid` argument. `arg3` is ignored. If `arg2` is non-zero,
interception is enabled for `pid`. Otherwise, it's disabled.

**You can check if whatever system call svc_stalker's patchfinder
decided to patch to `svc_stalker_ctl` was successfully patched by doing
`syscall(<patched syscall num>, -1, PID_MANAGE, 0, 0);`. 
If it has been patched correctly, it will return 999. `arg2` and `arg3` don't matter
in this case.**

For `CALL_LIST_MANAGE`, `arg2` is a call number, and `arg3` is a boolean. If
`arg3` is non-zero, `arg2` is added to `pid`'s call interception list. If zero,
`arg2` is deleted from that list.

For both `flavor` arguments, `0` is returned on success, unless you're checking
if `svc_stalker_ctl` was patched successfully.

### Errors
Upon error, `-1` is returned and `errno` is set.

#### General Errors
- Any `flavor` besides `PID_MANAGE` and `CALL_LIST_MANAGE` return an error. `errno` is
set to `EINVAL`.

#### Errors Pertaining to `PID_MANAGE`
`errno` is set to...
- `EINVAL` if...
    - `pid` is less than `-1`.
- `ENOENT` if...
    - You tried to turn off interception for a PID which never had it on.
- `ENOSPC` if...
    - The stalker table reached capacity. This should never happen as long as
you are removing PIDs you no longer wish to intercept calls for.
- `EEXIST` if...
    - You tried to add a PID which is already present inside the stalker table.

#### Errors Pertaining to `CALL_LIST_MANAGE`
`errno` is set to...
- `EINVAL` if...
    -  `arg2` is larger than `0x1fff` or smaller than `-0x1fff`. This check does
not apply for platform system calls.
- `ENOENT` if...
    - You tried to add a call number to intercept for a PID which isn't present
inside the stalker table.
- `ENOMEM` if...
    - `kalloc_canblock` fails.

`module/svc_stalker_ctl.s` implements `svc_stalker_ctl`. Please look in the
`example` directory for more usage.

### Notes

**FOR ANY PID YOU REGISTER FOR SYSTEM CALL/MACH TRAP INTERCEPTION, YOU MUST
ALSO UN-REGISTER WHEN YOU ARE DONE. Unregistering a previously-registered PID
will free the table entry for that PID.** It's also a good idea to save previous
exception ports before registering your own and restoring them when you're
done intercepting calls.

**A maximum of 1023 processes can have their system calls be intercepted
simultaneously.**

**You need to register exception ports for your process before you enable
system call interception for it.** Nothing checks if you've done this.

## Other Notes
At the moment, this project assumes a 16k page size. I've only tested this on
phones running iOS 13 and higher.

I try my best to make sure the patchfinder works on all kernels iOS 13+, so
if something isn't working, please file an issue.
