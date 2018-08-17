#!/bin/bash

echo "-------------------   start test " >> boetest_2.log
./boetest eno2 ./eccdata/rs0601_rsh.txt ./eccdata/rs0601_v.txt ./eccdata/rs0601_xy.txt &>> boetest_2.log
rst=$?
if [ $rst != 0 ];
then
	echo "board 2 test failed." >> boetest_2.log
fi
