#/!/bin/bash

#File: testscript
#Author: Andy Sayler
#Project: CSCI 3753 Programming Assignment 3
#Create Date: 2012/03/09
#Modify Date: 2012/03/21
#Description:
#	A simple bash script to run a signle copy of each test case
#	and gather the relevent data.

TIMEFORMAT="wall=%e user=%U system=%S CPU=%P i-switched=%c v-switched=%w"
MAKE="make -s"

echo Building code...
$MAKE clean
$MAKE

echo Starting test runs...

echo cpu tests

echo CPU w/ SCHED_OTHER & LOW
/usr/bin/time -f "$TIMEFORMAT" ./pi-sched $ITERATIONS SCHED_OTHER > /dev/null
