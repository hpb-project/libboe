#!/bin/bash
rm boetest_*.log

for i in {1..100}
do
	echo "test number $i"
	./power 1 1
	sleep 1
	./power 2 1
	sleep 1
	./power 3 1
	sleep 1
	./power 4 1
	sleep 1

	sleep 5

	./ptest_1.sh &
	./ptest_2.sh &
	./ptest_3.sh &
	./ptest_4.sh &

	sleep 9

	./power 1 0
	sleep 1
	./power 2 0
	sleep 1
	./power 3 0
	sleep 1
	./power 4 0

	sleep 10
done
ln_phy_error_1=`grep -nr 'phy is error' ./boetest_1.log | wc -l`
ln_phy_error_2=`grep -nr 'phy is error' ./boetest_2.log | wc -l`
ln_phy_error_3=`grep -nr 'phy is error' ./boetest_3.log | wc -l`
ln_phy_error_4=`grep -nr 'phy is error' ./boetest_4.log | wc -l`

ln_ecc_error_1=`grep -nr 'ecc test failed' ./boetest_1.log | wc -l`
ln_ecc_error_2=`grep -nr 'ecc test failed' ./boetest_2.log | wc -l`
ln_ecc_error_3=`grep -nr 'ecc test failed' ./boetest_3.log | wc -l`
ln_ecc_error_4=`grep -nr 'ecc test failed' ./boetest_4.log | wc -l`

echo "board_1 phy error cnt $ln_phy_error_1"
echo "board_2 phy error cnt $ln_phy_error_2"
echo "board_3 phy error cnt $ln_phy_error_3"
echo "board_4 phy error cnt $ln_phy_error_4"

echo "board_1 ecc error cnt $ln_ecc_error_1"
echo "board_2 ecc error cnt $ln_ecc_error_2"
echo "board_3 ecc error cnt $ln_ecc_error_3"
echo "board_4 ecc error cnt $ln_ecc_error_4"
