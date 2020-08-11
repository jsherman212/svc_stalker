usage: `mini_strace <pid>`

If you want to compile this, you need three other files: mach_excServer.c,
mach_excUser.c, and mach_exc.h. To get them, download latest XNU source, 
unzip it to some directory, `cd` to that directory, and do
`mig osfmk/mach/mach_exc.defs`. You'll find those three files in the same
directory you unzipped XNU source to.

This example program will register the `pid` argument and filter for `write`,
`open`, `access`, `mach_msg_trap`, and `_kernelrpc_mach_port_allocate_trap`.

Ctrl-C to stop.
