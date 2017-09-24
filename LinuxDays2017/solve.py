#!/usr/bin/env python3
import r2pipe

r2 = r2pipe.open('./runme', ['-d'])

while 'invalid' not in r2.cmd('s'):
    #  do one step + seek to rip register
    r2.cmd('ds;sr rip')

    json = r2.cmdj('pdj 1')

    if not json:
        continue

    json = json[0]
    opcode = json['opcode']

    if 'cmp byte [rcx]' in opcode:
        char = str(hex(json['ptr']))
        r2.cmd('wx {} @ rcx'.format(char))
        print(chr(int(char, 16)), end='', flush=True)

print()
