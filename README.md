# svc_catcher

svc_catcher is a pongoOS module which hooks XNU's `handle_svc` to
call `exception_triage`, sending a supervisor call Mach exception message to userland.

Requires `libusb`: `brew install libusb`
