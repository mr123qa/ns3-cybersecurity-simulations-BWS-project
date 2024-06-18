#!/bin/bash

mkdir delay

number_of_bots=(0 2 4 8 16 24 32 50 75 100 150 200)
for number in "${number_of_bots[@]}"
do
    for ((i=456; i>=446; i--))
    do
        echo $i
        ./ns3 run "scratch/DDoSim.cc --include_bots=false --record_delay=true --max_bulk_bytes=100000000 --number_of_bots=${number} --RngRun=$i"
    done

    mkdir -p delay/${number}
    mv DDoSIM-* delay/${number}/
done