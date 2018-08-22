#!/bin/bash

echo "-------------------   start test " >> boetest_1.log
./boetest enp0s31f6 ./eccdata/rs0601_rsh.txt ./eccdata/rs0601_v.txt ./eccdata/rs0601_xy.txt &>> boetest_1.log
rst=$?
if [ $rst != 0 ];
then
	echo "board 1 test failed." >> boetest_1.log
fi
