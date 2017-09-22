#!/usr/bin/env python3
import sys
import r2pipe

r2 = r2pipe.open('./runme', ['-w'])

sections = {section['name']: section for section in r2.cmdj('iSj')}
text_section = sections['LOAD1']
end_enc = text_section['vaddr'] + text_section['vsize']
print('Text section end: {}'.format(str(hex(end_enc))))

hits = r2.cmdj('/cj inc rcx')
enc_starts = [hit['offset'] for hit in hits]
keys = []

for enc_start in enc_starts:
    #  + 3 inc rcx
    enc = str(hex(enc_start + 3))
    key = str(hex(r2.cmdj('pdj 1 @ ' + enc)[0]['ptr']))
    keys.append(key)

#  do not encrypt the first block/letter
enc_starts.pop(0)
keys.pop()

for enc_start, key in zip(enc_starts, keys):
    enc = str(hex(enc_start))
    num_bytes = str(hex(end_enc - int(enc, 16)))
    cmd = 'wox {} @ {}!{}'.format(key, enc, num_bytes)
    print(cmd)
    r2.cmd(cmd)

#  set number of sections to 0
#  cripples objdump and gdb
cmd = 'e io.va = false'
print(cmd)
r2.cmd(cmd)
cmd = 'w0 1 @ 0x3c'
print(cmd)
r2.cmd(cmd)
