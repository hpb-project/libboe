#!/bin/bash
for i in {1..100000}
do
echo test number is $i
 ./rsutest enp0s31f6 rs0601_rsh.txt rs0601_v.txt rs0601_xy.txt
done

