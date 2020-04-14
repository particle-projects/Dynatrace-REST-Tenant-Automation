#!/bin/bash
# Script for calling patterns
set -x

cd /home/dynatrace/rta
## WebPageRequestSpamming
py rta.py easytravel plugin WebPageRequestSpamming true
sleep 30m

py rta.py easytravel plugin WebPageRequestSpamming false
sleep 2h

py rta.py easytravel plugin UsabilityIssue true
sleep 30m

py rta.py easytravel plugin UsabilityIssue false
