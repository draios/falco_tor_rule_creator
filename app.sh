#!/bin/bash

while [ 1 ]
do
  python /app/falco_tor_rule_creator.py --help # Replace --help with your options before building image
  sleep 1800 # 30 minutes
done