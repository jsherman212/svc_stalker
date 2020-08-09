# svc_stalker

svc_stalker is a pongoOS module which modifies XNU's `sleh_synchronous` to
call `exception_triage` on a supervisor call exception, sending a mach exception message to
userland exception ports. This message is sent before the system call/mach trap
happens, so you're free to view/modify registers inside your exception handler
before returning from it & giving control back to the kernel to carry out the
system call/mach trap.

When `catch_mach_exception_raise` is called, the call number is placed
in `code[0]`. `exception` will hold either `EXC_SYSCALL` or `EXC_MACH_SYSCALL`,
depending on what was intercepted.

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

## svc_stalker_ctl
svc_stalker will patch the first `sysent` struct in `_sysent` that has `sy_call`
point to `_enosys` to instead point to a custom system call, `svc_stalker_ctl`.
In my experience, the system call that ends up being patched is #8. In
case it isn't, the module prints the patched system call number to the
device's framebuffer anyway.

`svc_stalker_ctl` is your way of managing system call/Mach trap interception
for different processes. It takes four arguments, `pid`, `flavor`, `arg2`,
and `arg3`, respectively. `pid` is obviously the process you wish to interact
with. `flavor` is either `PID_MANAGE` (`0`) or `CALL_LIST_MANAGE` (`1`).

For `PID_MANAGE`, `arg2` controls whether or not system calls/Mach traps are intercepted
for the `pid` argument. `arg3` is ignored. If `arg2` is non-zero, interception is enabled for `pid`. Otherwise, it's disabled.

**You can check if whatever system call svc_stalker's patchfinder
decided to patch to `svc_stalker_ctl` was successfully patched by doing
`syscall(<patched syscall num>, -1, PID_MANAGE, 0, 0);`. 
If it has been patched correctly, it will return 999. `arg2` and `arg3` don't matter
in this case.**

For `CALL_LIST_MANAGE`, `arg2` is a call number, and `arg3`, if
non-zero, adds, or if zero, deletes, `arg2` from the internally-managed list of
system calls/Mach traps to intercept for the `pid` argument.

For both `flavor` arguments, `0` is returned on success, unless you're checking
if `svc_stalker_ctl` was patched successfully.

### Errors
Upon error, `-1` is returned and `errno` is set to `EINVAL` or `ENOMEM`.

#### General Errors
- Any `flavor` besides `PID_MANAGE` and `CALL_LIST_MANAGE` return an error. `errno` is
set to `EINVAL`.

#### Errors Pertaining to `PID_MANAGE`
`errno` is set to `EINVAL` if...
- `pid` was less than `-1`.
- You tried to turn off system call/Mach trap interception for a PID which
never had it on to begin with.
- The internally-managed table of PIDs reached capacity. This should never happen,
as long as you are removing PIDs which you no longer wish to intercept
system calls/Mach traps for.

#### Errors Pertaining to `CALL_LIST_MANAGE`
`errno` is set to `ENOMEM` if...
- `kalloc_canblock` fails.

`errno` is set to `EINVAL` if...
- You tried to add a system call/Mach trap to intercept for a PID that hasn't had
interception enabled yet.
- There are no more free slots in the internally-managed list of system
calls/Mach traps to intercept for a given PID. This should never happen, as the limit
is much, much higher than the number of available system calls/Mach traps.
- You tried to turn off interception for a system call/Mach trap which
never had it on to begin with.

`module/svc_stalker_ctl.s` implements `svc_stalker_ctl`. Please look in the
`example` directory for more usage.

### Notes

**FOR ANY PID YOU REGISTER FOR SYSTEM CALL/MACH TRAP INTERCEPTION, YOU MUST
ALSO UN-REGISTER WHEN YOU ARE DONE. Unregistering a previously-registered PID
will free the table entry for that PID.**

**A maximum of 1023 processes can have their system calls be intercepted
simultaneously.**

**You need to register exception ports for your process before you enable
system call interception for it.** Nothing checks if you've done this to
save space.

## Known Issues
Sometimes a couple of my phones won't boot after checkra1n's patchfinder
finished. I have yet to figure out what causes this, but if this happens,
try again. Also, if the device hangs after `bootx`, try again.

## Other Notes
At the moment, this project assumes a 16k page size. I've only tested this on
phones running iOS 13 and higher.
