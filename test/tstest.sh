#!/bin/bash
declare -i i=1
#
#while ((i<100));do
#    sudo ./tstest enp0s31f6 urstest >> b.log ;
#    let ++i;
#    if [ "$?" == "0" ];then
#        continue;
#    else
#        break;
#    fi
#done

while ((i<2));do
    sudo ./tstest enp0s31f6 urstest ;
    let ++i;
    if [ "$?" == "0" ];then
        continue;
    else
        break;
    fi
done
