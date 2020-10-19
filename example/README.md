usage: `mini_strace <pid>`

`mini_strace` will register the `pid` argument and filter for a bunch of
different system calls and Mach traps.

If you want to compile this, you need three other files: mach_excServer.c,
mach_excUser.c, and mach_exc.h. To get them, download latest XNU source, 
unzip it to some directory, `cd` to that directory, and do
`mig osfmk/mach/mach_exc.defs`. You'll find those three files in the same
directory you unzipped the XNU source to.

Ctrl-C to stop.

To build (on device):
```
clang-10 -Wno-deprecated-declarations -isysroot <your SDK> mach_excUser.c mach_excServer.c array.c mini_strace.c -o mini_strace 
ldid -Sent.xml -P ./mini_strace
```

**Note:** `svc_stalker.h` is meant to be included in all programs which utilize
svc_stalker's call interception. That header contains constants for
`svc_stalker_ctl` and limits for the internal data structures svc_stalker
manages.
