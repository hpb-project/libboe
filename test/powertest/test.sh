#!/bin/bash
rm boetest_*.log

for i in {1..100}
do
	echo "test number $i"
	./power 1 1

	sleep 7

	./ptest_1.sh &

	sleep 9

	./power 1 0
	sleep 10
done
ln_ecc_error_1=`grep -nr 'ecc test failed' ./boetest_1.log | wc -l`

echo "board_1 ecc error cnt $ln_ecc_error_1"
