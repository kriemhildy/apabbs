#!/bin/bash
# This script creates a compressed backup of the application database
# Useful for backups, migrations, or creating test data snapshots

# Print each command before executing (useful for debugging)
set -x

# Create a database dump using PostgreSQL's pg_dump utility
# Uses the DATABASE_URL environment variable to connect to the database
# The 'nice' command reduces CPU priority to avoid impacting system performance
nice pg_dump $DATABASE_URL > apabbs.sql

# Compress the SQL dump file using gzip for smaller file size
# The --force flag overwrites any existing gzip file with the same name
nice gzip --force apabbs.sql
