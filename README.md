# svc_stalker

svc_stalker is a pongoOS module which hooks XNU's `handle_svc` to
call `exception_triage`, sending a mach exception message to
userland exception ports. This message is sent before the system call/mach trap
happens, so you're free to view/modify registers inside your exception handler
before returning from it & giving control back to the kernel to carry out the
system call/mach trap.

The system call/mach trap number is placed in code[0] of the exception
message sent for convenience.

Requires `libusb`: `brew install libusb`

Requires `perl`: `brew install perl`

## Building
Run `make` inside the top level directory. It'll automatically build the loader
and the `svc_stalker` module.

## Usage
After you've built everything, have checkra1n boot your device to a pongo
shell: `/Applications/checkra1n.app/Contents/MacOS/checkra1n -p`

After the device is booted to pongoOS, and in the same directory you built
the loader and the `svc_stalker` module, do `loader/loader module/svc_stalker`.
`svc_stalker` will patch the kernel and in a few seconds XNU will boot.

## svc_stalker_ctl
svc_stalker will patch the first `sysent` struct in `_sysent` that has `sy_call`
point to `_enosys` to instead point to a custom system call, `svc_stalker_ctl`.
In my experience, the system call that ends up being patched is #8. In
case it isn't, the module prints the patched system call number to the
device's framebuffer anyway.

`svc_stalker_ctl` is your way of managing system call interception
for different processes. It takes four arguments, `pid`, `flavor`, `arg2`,
and `arg3`, respectively. `pid` is obviously the process you wish to interact
with. `flavor` is either `PID_MANAGE` (`0`) or `SYSCALL_MANAGE` (`1`). All other
`flavor` values return `-1` with `errno` set to `EINVAL`.

For `PID_MANAGE`, `arg2` controls whether or not system calls are intercepted
for the `pid` argument. `arg3` is ignored. If `arg2` is non-zero, system calls
will be intercepted for `pid`. Otherwise, system calls won't be intercepted
for `pid`. **You can check if whatever system call svc_stalker's patchfinder
decided to patch to `svc_stalker_ctl` was successfully patched by doing
`syscall(<patched syscall num>, -1, PID_MANAGE, 0, 0);`. 
If it has been patched correctly, it will return 999. `arg2` and `arg3` don't matter
in this case.** If `pid` doesn't make sense, and if you aren't checking
if `svc_stalker_ctl` was patched correctly, `-1` is returned and `errno` is set
to `EINVAL`. The same goes for if you try and disable a PID which was never
enabled. If you enable an already-enabled PID, nothing happens.

For `SYSCALL_MANAGE`, `arg2` is a system call number, and `arg3`, if
non-zero, adds, or if zero, deletes, `arg2` from the internally-managed list of
system calls to intercept for the `pid` argument. If system call interception
is not enabled for `pid`, all calls to `svc_stalker_ctl` with `SYSCALL_MANAGE`
as `flavor` return `-1` with `errno` set to `EINVAL`. If `kalloc_canblock`
fails for a new call list allocation, `-1` is returned and `errno` is set to
`ENOMEM`. If you try to delete a system call which was never added, `-1` is
returned and `errno` is set to `EINVAL`. If the call list is full (which it shouldn't
ever be), `-1` is returned and `errno` is set to `EINVAL`.

For both `flavor` arguments, `0` is returned on success, unless you're checking
if `svc_stalker_ctl` was patched successfully.

`module/svc_stalker_ctl.s` implements `svc_stalker_ctl`. Please look in the
`example` directory for more usage.

**FOR ANY PID YOU REGISTER FOR SYSTEM CALL/MACH TRAP INTERCEPTION, YOU MUST
ALSO UN-REGISTER WHEN YOU ARE DONE. Unregistering a previously-registered PID
will free the `stalker_ctl` struct for that PID.**

**A maximum of 1023 processes can have their system calls be intercepted
simultaneously.** If you try and intercept system calls for a 1024th process,
`-1` is returned and `errno` is set to `EINVAL`.

**You need to register exception ports for your process before you enable
system call interception for it.** The `handle_svc` hook doesn't check if
you've done this to save space.

Ideally, I'd have as much space as I need to write `svc_stalker_ctl` and
the `handle_svc` hook. Unfortunately, I have no way of marking memory returned by
`alloc_static` as executable, so I use the space at the end of the very last
section of `__TEXT_EXEC` that forces it to be page-aligned as executable
scratch space. In the future, I plan to do away with putting everything inside
this scratch space. Instead, I want to use this space to execute a small amount
of code which modifies the page tables of `alloc_static`'ed memory to mark it
as executable.

## Other Notes
At the moment, this project assumes a 16k page size.
