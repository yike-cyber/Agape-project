#!/bin/bash

set -e  # Exit on error

# Install dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Make sure the media directory exists
mkdir -p media

# Apply database migrations
python manage.py makemigrations
python manage.py migrate
