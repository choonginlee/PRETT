#!/bin/bash
###############################################################################
# bincov performance test script
###############################################################################
echo "PATH"
time for i in $(seq 1 1 50)
do
    _build/bin32/drrun -32 -c _build/clients/bincov/bin/libbincov.so `echo -en 'cat/p/3'` -- /bin/cat < /dev/null &> /dev/null
done

echo "NODE"
time for i in $(seq 1 1 50)
do
    _build/bin32/drrun -32 -c _build/clients/bincov/bin/libbincov.so `echo -en 'cat/n/3'` -- /bin/cat < /dev/null &> /dev/null
done
