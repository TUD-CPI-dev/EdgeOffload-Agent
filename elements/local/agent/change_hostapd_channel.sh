#!/bin/bash

# pid=$(ps aux | grep hostapd | grep -v "grep" | awk '{print $2}')
echo $(($(date +%s%N)/1000000))

channel=$1

sed -ir "s/channel=[0-9]*$/channel=${channel}/" /home/yfliu/Downloads/hostapd-2.0/hostapd/test.conf
killall -9 hostapd

cd /home/yfliu/Downloads/hostapd-2.0/hostapd/
./hostapd test.conf &

echo $(($(date +%s%N)/1000000))

exit 0