# svc_catcher

PongoOS module which hooks XNU's `handle_svc` to call `exception_triage`,
sending a supervisor call Mach exception message to userland.
