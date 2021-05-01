#!/bin/sh
echo "Number of Guards: $1"
wait
python3 experiments.py 1 $1 0
wait
python3 experiments.py 2 $1 100
wait
python3 experiments.py 5 $1 200
wait
python3 experiments.py 10 $1 300
wait
python3 experiments.py 20 $1 400
wait
python3 experiments.py 50 $1 1000
wait
python3 experiments.py 100 $1 2000
wait
python3 experiments.py 200 $1 3000
wait
python3 experiments.py 500 $1 4500
wait
#python3 experiments.py 1000 1s