#!/bin/bash
rm boetest_*.log

for i in {1..100}
do
	echo "test number $i"
    ./boetest enp0s31f6 ./eccdata/rs0601_rsh.txt ./eccdata/rs0601_v.txt ./eccdata/rs0601_xy.txt &>> boetest_1.log
    rst=$?
    if [ $rst != 0 ];
    then
        echo "board test failed." >> boetest_1.log
    fi
    sleep 2
done
ln_ecc_error_1=`grep -nr 'ecc test failed' ./boetest_1.log | wc -l`

echo "board_1 ecc error cnt $ln_ecc_error_1"
