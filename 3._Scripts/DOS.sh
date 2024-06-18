#!/bin/bash

mkdir DOS

ddos_rates=(1 1024 2048 4096 6144 8192 10240 12288 14336 16384 18432 20480)
for rate in "${ddos_rates[@]}"
do
    for ((i=456; i>=446; i--))
    do
        echo $i
        ./ns3 run "scratch/DDoSim.cc --number_of_bots=1 --ddos_rate="${rate}kb/s" --RngRun=$i"
    done

    mkdir DOS/${rate}
    mv DDoSIM-* DOS/${rate}/
done
