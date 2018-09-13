#!/bin/bash

if [ $# -lt 1 ];
then
    echo "Usage $0 sn"
    exit 1
fi

SN_PREFIX=10001012018080800

sn_mac_file=sn_mac.txt
info_file=china_info.txt
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

find_sn_ln=`grep -n "$SN" $sn_mac_file | cut -f1 -d:`
sn_and_mac=`grep -n "$SN" $sn_mac_file | cut -f2 -d:`
sn_and_mac_col_num=`echo $sn_and_mac | awk '{print NF}'`
if [ ! -n "$sn_and_mac" ];
then
    echo "$SN is not find, please recheck"
fi

if [ $sn_and_mac_col_num -gt 2 ];
then
    echo "the sn($SN) has been used."
    exit 1
fi
echo "SN=$SN"
mac=`echo $sn_and_mac | awk '{print $2}'`

fline_num=`wc -l $info_file | awk '{print $1}'`
if [ $fline_num -gt 0 ];
then
    content=`head -1 $info_file`
    col_n=`echo "$content" | awk '{print NF}'`
    if [ $col_n -ne 2 ];
    then
        echo "content($content) format invalid."
        exit 1
    fi
    account=`echo $content | awk '{print $1}'`
    hid=`echo $content | awk '{print $2}'`
    remote=`./bawriteinfo $SN $mac $account 2>error.log`
    if [ $? -eq 0 ];
    then
        r_n=`echo $remote | awk '{print NF}'`
        if [ $r_n -eq 4 ];
        then
            rsn=`echo $remote | awk '{print $1}'`
            rmac=`echo $remote | awk '{print $2}'`
            raccount=`echo $remote | awk '{print $3}'`
            rcid=`echo $remote | awk '{print $4}'`
            sed -i "${find_sn_ln}s/$/& used/g" $sn_mac_file
            sed -i "1d" $info_file
            echo -e "$raccount\t$hid\t$rsn\t$rmac\t$rcid" >> ${info_file}_full.txt
            echo "write finished"
        else
            echo "write info return value ($remote) error"
        fi
    else
        echo "write info failed:"
        cat error.log
        exit 1
    fi
else
    echo "have no content in $info_file"
    exit 1
fi



