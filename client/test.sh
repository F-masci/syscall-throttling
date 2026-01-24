#!/bin/bash

IDX=${1:-0}

while [ true ]; do
    mkdir test$IDX
    rm -r test$IDX
done