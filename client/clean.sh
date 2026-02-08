#!/bin/bash

sudo ./client remove --sys 83
sudo ./client remove --sys 34
sudo ./client remove --prog $(./devn.sh ./pause)
# sudo ./client remove --prog ./pause
sudo ./client remove --prog /usr/bin/mkdir
sudo ./client remove --uid 1000