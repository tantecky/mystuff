#!/bin/bash
make
result=$(./solve.py 2> /dev/null)
[[ "$result" == "L1nuxDayZ" ]] && echo OK || echo FAILED
