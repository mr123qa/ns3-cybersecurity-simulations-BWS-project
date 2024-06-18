#!/bin/bash

mkdir DDOS

number_of_bots=(1 2 4 6 8 10 12 14 16 18 20)
for number in "${number_of_bots[@]}"
do
    for ((i=456; i>=446; i--))
    do
        echo $i
        ./ns3 run "scratch/DDoSim.cc --number_of_bots=${number} --ddos_rate="1024kb/s" --RngRun=$i"
    done

    mkdir -p DDOS/${number}
    mv DDoSIM-* DDOS/${number}/
done
