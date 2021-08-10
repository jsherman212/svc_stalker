# svc_stalker

![alt text](https://github.com/jsherman212/svc_stalker/blob/master/mini_strace.png)

<sup>*Output from intercepting some calls for Call of Duty: Mobile from
example/mini_strace.c*</sup>

# This project has been made obsolete by [xnuspy](https://github.com/jsherman212/xnuspy)

svc_stalker is a pongoOS module which modifies XNU to call `exception_triage`
during supervisor call exceptions, sending a Mach exception message to userland
exception ports.

svc_stalker supports iOS 13.x and iOS 14.x on checkra1n 0.11.0 and up. Devices
with a 4K page size are not supported.

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

svc_stalker adds a new sysctl, `kern.svc_stalker_ctl_callnum`, so you can
figure out which system call was patched to `svc_stalker_ctl`:

```
size_t oldlen = sizeof(long);
long SYS_svc_stalker_ctl = 0;
sysctlbyname("kern.svc_stalker_ctl_callnum", &SYS_svc_stalker_ctl, &oldlen, NULL, 0);
```

Requires `libusb`: `brew install libusb`

Requires `perl`: `brew install perl`

## Building
Run `make` inside the top level directory. It'll build the loader and the module.

## Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

In the same directory you built the loader and the module, do
`loader/loader module/svc_stalker`. svc_stalker will patch XNU and in a few
seconds your device will boot. `loader` will wait a couple more seconds after
issuing `stalker-getkernelv` in case SEPROM needs to be exploited.

## Known Issues
Sometimes a couple of my phones would get stuck at "Booting" after checkra1n's KPF
runs. I have yet to figure out what causes this, but if it happens, try again.
Also, if the device hangs after `bootx`, try again.

## svc_stalker_ctl
svc_stalker will patch the first `_enosys` system call to instead represent
`svc_stalker_ctl`. You can find its implementation at `module/el1/svc_stalker_ctl.s`
and example usage at `example/mini_strace.c`.

`svc_stalker_ctl` is your way of managing call interception for different
processes. It takes four arguments, `pid`, `flavor`, `arg2`, and `arg3`,
respectively. `pid` is obviously the process you wish to interact with.
`flavor` is either `PID_MANAGE` (`0`) or `CALL_LIST_MANAGE` (`1`).

For `PID_MANAGE`, `arg2` controls whether or not calls are intercepted for
`pid`. `arg3` is ignored. If `arg2` is non-zero, interception is enabled for
`pid`. Otherwise, it's disabled. Enabling call interception for `pid` creates
a table entry for it. When you disable call interception, its table entry and
call list (if present) are freed.

For `CALL_LIST_MANAGE`, `arg2` is a call number, and `arg3` is a boolean. If
`arg3` is non-zero, interception for `arg2` is enabled for `pid`. Otherwise,
it's disabled. The call list for `pid`'s table entry is created the first time
you add a call number to intercept.

For both `flavor` arguments, `0` is returned on success.

**You can check if `svc_stalker_ctl` is working right by doing
`syscall(<svc_stalker_ctl's syscall number>, -1, PID_MANAGE, 0, 0);`. 
If it is working correctly, it will return 999. `arg2` and `arg3` don't matter
in this case.**

### Errors
Upon error, `-1` is returned and `errno` is set.

#### General Errors
- Any `flavor` besides `PID_MANAGE` and `CALL_LIST_MANAGE` return an error
and `errno` is set to `EINVAL`.

#### Errors Pertaining to `PID_MANAGE`
`errno` is set to...
- `EINVAL` if:
    - `pid` is less than `-1`.
- `ENOENT` if:
    - You tried to disable call interception for `pid` when it was never enabled.
- `ENOSPC` if:
    - There are no more free table entries. This should never happen as long as
you are disabling interception for PIDs you no longer wish to intercept calls for.
- `EEXIST` if:
    - You tried to enable call interception for `pid` when it was already enabled.

#### Errors Pertaining to `CALL_LIST_MANAGE`
`errno` is set to...
- `EINVAL` if:
    -  `arg2` is larger than `0x1fff` or smaller than `-0x1fff`. This check does
not apply for platform system calls (call number `0x80000000`)
- `ENOENT` if:
    - Call interception is not enabled for `pid`.
- `ENOMEM` if:
    - `kalloc_canblock` or `kalloc_external` fails while allocating `pid`'s call list.

## Other Notes
**You need to register exception ports for your process before you enable
call interception for it.** Nothing checks if you've done this.

**FOR ANY PID YOU REGISTER FOR SYSTEM CALL/MACH TRAP INTERCEPTION, YOU MUST
ALSO UN-REGISTER WHEN YOU ARE DONE. Unregistering a previously-registered PID
will free its table entry.** It's also a good idea to save previous
exception ports before registering your own and restoring them when you're
done intercepting calls.

**A maximum of 1023 processes can have their calls intercepted simultaneously.**

I try my best to make sure the patchfinder works on all kernels iOS 13+, so
if something isn't working, please file an issue.
