#!/bin/bash
# Assumes envsubst is installed and ghfs_config.template exists  
[ ! -d mountpoint ] && mkdir mountpoint
ENTITYFS_CONFIG=example.ini python3 entityfs.py mountpoint -o allow_other,nonempty
ls mountpoint
