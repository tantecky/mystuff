#!/usr/bin/env python3
import sys
import r2pipe
#  skip the first 3 syscalls
SYSCALLS_2_SKIP = 3

#  open the binary with attached debugger
r2 = r2pipe.open('./runme', ['-d', '-2'])

try:
    while 'invalid' not in r2.cmd('s'):
        #  do one step + seek to rip register
        r2.cmd('ds;sr rip')

        # dissamble one instruction
        json = r2.cmdj('pdj 1')

        if not json:
            continue

        json = json[0]
        opcode = json['opcode']

        if opcode == 'syscall' and SYSCALLS_2_SKIP:
            SYSCALLS_2_SKIP -= 1
            r2.cmd('dss')
            continue

        #  identify an instruction with a password
        if 'cmp byte [rcx]' in opcode:
            #  extract next character of a password
            char = str(hex(json['val']))
            # write the character to stack
            r2.cmd('wx {} @ rcx'.format(char))
            #  print the character
            print(chr(int(char, 16)), end='', flush=True)
except:
    pass

print()
