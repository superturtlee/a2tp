savedcmd_a2tp.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o a2tp.o @a2tp.mod  ; /usr/src/linux-headers-7.0.0-30-generic/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --retpoline --rethunk --sls --stackval --static-call --uaccess --prefix=16  --link  --module a2tp.o

a2tp.o: $(wildcard /usr/src/linux-headers-7.0.0-30-generic/tools/objtool/objtool)
