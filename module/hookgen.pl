#!/usr/bin/perl

system("clang -O0 -arch arm64 -isysroot \$(xcrun --sdk iphoneos --show-sdk-path) handle_svc_hook.s -o handle_svc_hook");
system("otool -jtVX handle_svc_hook | tail -n +2 > dis");

open(DISFILE, "<dis") or die("Couldn't open dis file");

open(HEADER, ">handle_svc_patches.h") or die("Couldn't open handle_svc_patches.h");

printf(HEADER "#ifndef handle_svc_patches\n");
printf(HEADER "#define handle_svc_patches\n");

printf(HEADER "#define DO_HANDLE_SVC_PATCHES \\\n");

my $curlabel;
# space used for caching offsets will also be counted as instructions
my $cache_space = 0x8;
my $instr_count = $cache_space / 4;

# testing, iphone 8 13.6
my $curkaddr = 0xFFFFFFF0156B7230 + $cache_space;

while(my $line = <DISFILE>){
    chomp($line);

    if($line =~ /([a-f0-9]+)\s([a-f0-9]+)\s([a-f0-9]+)\s([a-f0-9]+)\s(.*)/g){
        $instr_count += 1;

        if($curlabel){
            printf(HEADER "/*                                           %-35s*/ \\\n", "$curlabel:");
        }

        printf(HEADER "WRITE_INSTR(0x$4$3$2$1); /* %#x    %-30s*/", $curkaddr, "$5");
        $curkaddr += 4;

        if(eof){
            printf(HEADER " \n");
        }
        else{
            printf(HEADER " \\\n");
        }

        undef $curlabel;
    }
    elsif($line =~ /([_\w\d]+):/g){
        $curlabel = $1;
    }
}

printf(HEADER "#endif\n");

# iphone 7
#printf("$instr_count/1206 instructions\n");
