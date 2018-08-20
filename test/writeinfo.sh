#!/bin/bash

if [ $# -lt 1 ];
then
    echo "Usage $0 sn"
    exit 1
fi

SN_PREFIX=10001012018080800

info_file=810_boardinfo.txt
sn=$1
SN=
lensn=`expr length $sn`
if [ $lensn -eq 1 ];
then
    SN=${SN_PREFIX}00${sn}
elif [ $lensn -eq 2 ];
then
    SN=${SN_PREFIX}0${sn}
elif [ $lensn -eq 3 ];
then
    SN=${SN_PREFIX}${sn}
elif [ $lensn -gt 3 ];
then
    echo "sn($sn) is too bigger."
else
    echo "sn($sn) error."
    exit 1
fi
echo "SN=$SN"

find_l_num=`grep -n "$SN" $info_file | cut -f1 -d:`
content=`grep -n "$SN" $info_file | cut -f2 -d:`
col_n=`echo "$content" | awk '{print NF}'`
if [ ! -n "$col_n" ];
then
    echo "Not find $SN in $info_file, please recheck"
elif [ $col_n -eq 4 ];
then
    account=`echo $content | awk '{print $1}'`
    hid=`echo $content | awk '{print $2}'`
    ssn=`echo $content | awk '{print $3}'`
    mac=`echo $content | awk '{print $4}'`
    echo "account=$account"
    echo "hid=$hid"
    echo "sn=$ssn"
    echo "mac=$mac"
    #remote="$ssn $mac $account 111121231213213213213213213 "
    remote=`./bawriteinfo $ssn $mac $account 2>/dev/null`
    if [ $? -eq 0 ];
    then
        r_n=`echo $remote | awk '{print NF}'`
        if [ $r_n -eq 4 ];
        then
            rsn=`echo $remote | awk '{print $1}'`
            rmac=`echo $remote | awk '{print $2}'`
            raccount=`echo $remote | awk '{print $3}'`
            rcid=`echo $remote | awk '{print $4}'`
            sed -i "${find_l_num}s/$/& $remote/g" $info_file
        else
            echo "write info return value ($remote) error"
        fi
    else
        echo "write info failed"
    fi
else
    echo "This line info is not right: $content"
fi

