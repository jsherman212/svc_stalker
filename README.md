# svc_stalker

svc_stalker is a pongoOS module which hooks XNU's `handle_svc` to
call `exception_triage`, sending a supervisor call Mach exception message to
userland exception ports.

Requires `libusb`: `brew install libusb`
