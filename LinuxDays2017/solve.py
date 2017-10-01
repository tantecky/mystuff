#!/usr/bin/env python3
import r2pipe

#  open the binary with attached debugger
r2 = r2pipe.open('./runme', ['-d'])

while 'invalid' not in r2.cmd('s'):
    #  do one step + seek to rip register
    r2.cmd('ds;sr rip')

    # dissamble one instruction
    json = r2.cmdj('pdj 1')

    if not json:
        continue

    json = json[0]
    opcode = json['opcode']

    #  identify an instruction with a password
    if 'cmp byte [rcx]' in opcode:
        #  extract next character of a password
        char = str(hex(json['ptr']))
        # write the character to stack
        r2.cmd('wx {} @ rcx'.format(char))
        #  print the character
        print(chr(int(char, 16)), end='', flush=True)

print()
