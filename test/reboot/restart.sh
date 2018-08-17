#!/bin/bash
export PATH=$PATH:/bin:/sbin:/usr/bin

Total=1000
echo "1" >>/root/reboot/restart.ttl
ln=`wc -l /root/reboot/restart.ttl|awk '{print $1}'`
if [ $ln -lt $Total ];
then
    /root/reboot/boecheck >>/root/reboot/boecheck.log
    reboot
else
    crontab -r
fi

