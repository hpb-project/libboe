#!/bin/bash

echo "-------------------   start test " >> boetest_3.log
./boetest eno3 ./eccdata/rs0601_rsh.txt ./eccdata/rs0601_v.txt ./eccdata/rs0601_xy.txt &>> boetest_3.log
rst=$?
if [ $rst != 0 ];
then
	echo "board 3 test failed." >> boetest_3.log
fi
