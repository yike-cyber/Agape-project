#!/bin/bash
# Install dependencies
python-m pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Make migrations and migrate
python manage.py makemigrations
python manage.py migrate
