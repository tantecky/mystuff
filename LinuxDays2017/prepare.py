#!/usr/bin/env python3
import r2pipe
from json import loads

r2 = r2pipe.open('./runme', ['-w'])

sections = {section['name']: section for section in r2.cmdj('iSj')}
text_section = sections['.mytext']
end_enc = int(text_section['vaddr']) + int(text_section['vsize'])
print('Text section end: {}'.format(str(hex(end_enc))))

r2.cmd('/a inc rcx')

hits = []
for hit in loads(r2.cmd('fj')):
    if 'hit' in hit['name']:
        hits.append(hit)

enc_starts = [hit['offset'] for hit in hits]
keys = []

for enc_start in enc_starts:
    #  + 3 inc rcx
    enc = str(hex(enc_start + 3))
    key = str(hex(r2.cmdj('pdj 1 @ ' + enc)[0]['val']))
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
