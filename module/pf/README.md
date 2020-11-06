Directory structure:

13/
- patchfinder code for iOS 13.x

14/
- patchfinder code for iOS 14.x

disas.c
- contrary to the file name, assembler and disassembler

macho.c
- functions to work with Mach-O files

offsets.h
- offsets for the stalker cache and stalker_main_patcher

pf_common.h
- definition for `struct pf` and a bunch of macros related to its
initialization

pfs.h
- array of `pf` structs which represent svc_stalker's patchfinders

ss_patcher.c
- code to patch sleh_synchronous (stalker_main_patcher)
