#!/bin/bash

Ethname_1=enp0s31f6
Ethname_2=enp0s31f5
Ethname_3=enp0s31f4
Ethname_4=enp0s31f3

rm *.log -f
for i in {1..20000}
do
    echo test number is $i
    ./rsutest $Ethname_1 rs0601_rsh.txt rs0601_v.txt rs0601_xy.txt 
    #./rsutest $Ethname_1 rs0601_rsh.txt rs0601_v.txt rs0601_xy.txt >>$Ethname_1.log 2>&1 &
    #./rsutest $Ethname_2 rs0601_rsh.txt rs0601_v.txt rs0601_xy.txt >>$Ethname_2.log 2>&1 &
    #./rsutest $Ethname_3 rs0601_rsh.txt rs0601_v.txt rs0601_xy.txt >>$Ethname_3.log 2>&1 &
    sleep 8
done

