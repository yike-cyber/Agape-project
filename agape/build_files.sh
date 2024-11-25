#!/bin/bash

echo "BUILD START"

# Use Python 3.11 for all commands
python3.9 -m pip install --upgrade pip  # Upgrade pip to avoid compatibility issues
python3.9 -m pip install -r requirements.txt  # Install dependencies
python3.9 manage.py collectstatic --noinput --clear  # Collect static files
python3.9 manage.py migrate --noinput  # Run migrations

echo "BUILD END"
