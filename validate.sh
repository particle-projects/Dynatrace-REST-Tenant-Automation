#!/bin/bash
# Script for calling patterns
set -x

cd /home/dynatrace/rta
date
echo "validating"
py rta.py validate
