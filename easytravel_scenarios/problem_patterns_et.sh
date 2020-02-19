#!/bin/bash
# Script for calling patterns
set -x

## WebPageRequestSpamming
py rta.py easytravel plugin WebPageRequestSpamming true
sleep 15m

py rta.py easytravel plugin WebPageRequestSpamming false
sleep 30m

## LoginProblems
py rta.py easytravel plugin LoginProblems true
sleep 15m

py rta.py easytravel plugin LoginProblems false
sleep 30m

## AngularBookingError500
py rta.py easytravel plugin AngularBookingError500 true
sleep 15m

py rta.py easytravel plugin AngularBookingError500 false
sleep 30m

py rta.py easytravel plugin UsabilityIssue true
sleep 15m

py rta.py easytravel plugin UsabilityIssue false
sleep 30m
