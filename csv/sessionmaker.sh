#!/bin/bash 
## Shell function that creates multiple sub files for the different sessions.
#

i=0
for session in monday1 monday2 tuesday1 tuesday2
  do
  i=$((i+1))
  file=perform$i.csv
  printf "$i - creating csv $file \n"
  # Creating Header
  cat performall.csv | grep lastName > $file
  # Creating Content
  cat performall.csv | grep $session >> $file
done
