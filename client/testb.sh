#!/bin/bash

MAX_IDX=${1:-10}

for IDX in $(seq 0 $MAX_IDX); do
    ./test.sh $IDX &
done