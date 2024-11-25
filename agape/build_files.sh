#!/bin/bash

echo "BUILD START"

python3.9 -m pip install --upgrade pip  
python3.9 -m pip install -r requirements.txt  
python3.9 manage.py collectstatic --noinput --clear 
python3.9 manage.py migrate --noinput  # Run migrations

echo "BUILD END"
