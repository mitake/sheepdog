#! /bin/bash

# testing sockfd shrink with transparent fd consuming

sudo killall -KILL sheep
sudo killall -KILL shepherd

sudo rm -rf /tmp/sheepdog/dynamorio/*

sudo shepherd

sudo ~/dynamorio/build/bin64/drrun -c libemfile.so 1000 -- \
    sheep -d -c shepherd:127.0.0.1 -p 7000 -z 0 /tmp/sheepdog/dynamorio/0

for i in `seq 1 5`;
do
    sudo sheep -d -c shepherd:127.0.0.1 -p 700$i -z $i\
        /tmp/sheepdog/dynamorio/$i
done

sleep 3
collie cluster format

collie vdi create -P test 100M
