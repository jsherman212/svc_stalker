There are a few "rules" when dealing with kernel hooks:
- You cannot clobber temp registers `x9-x15` because you have no idea if
what we return back to depends on those registers.

- Be very careful when modifying `sleh_synchronous_hijacker`. If you cause a
crash, the kernel will call `sleh_synchronous`, which will call
`sleh_synchronous_hijacker`, then you'll crash and the kernel will call
`sleh_synchronous`, which will call `sleh_synchronous_hijacker` which will
crash... and on and on until the stack is corrupted.
