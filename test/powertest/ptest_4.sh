#!/bin/bash

echo "-------------------   start test " >> boetest_4.log
./boetest eno4 ./eccdata/rs0601_rsh.txt ./eccdata/rs0601_v.txt ./eccdata/rs0601_xy.txt &>> boetest_4.log
rst=$?
if [ $rst != 0 ];
then
	echo "board 4 test failed." >> boetest_4.log
fi
