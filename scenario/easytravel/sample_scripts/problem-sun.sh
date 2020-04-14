#!/bin/bash
# Script for calling patterns
set -x

cd /home/dynatrace/rta
echo "starting patterns"
date
## LoginProblems
py rta.py easytravel plugin LoginProblems true
sleep 30m

py rta.py easytravel plugin LoginProblems false
sleep 2h

## AngularBookingError500
py rta.py easytravel plugin AngularBookingError500 true
sleep 30m

py rta.py easytravel plugin AngularBookingError500 false

date
echo "problems solved"
