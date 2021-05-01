#!/bin/sh
echo "Number of Processes: $1"
echo "Number of Guards: $2"
wait
python3 experiments.py 1 1
wait
python3 experiments.py 50 1
wait
python3 experiments.py 100 1
wait
python3 experiments.py 1000 1
