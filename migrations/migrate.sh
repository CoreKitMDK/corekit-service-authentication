#!/bin/bash

set -e

# The script assumes it's being run from the 'migrations' directory.
if [ -f ".env" ]; then
  export $(cat .env | sed 's/#.*//g' | xargs)
fi

# Check for required environment variables
if [ -z "$PGUSER" ] || [ -z "$PGPASSWORD" ] || [ -z "$PGHOST" ] || [ -z "$PGPORT" ] || [ -z "$PGDATABASE" ]; then
  echo "One or more required environment variables are not set."
  echo "Please create a .env file in the migrations directory with the following variables:"
  echo "PGUSER, PGPASSWORD, PGHOST, PGPORT, PGDATABASE"
  exit 1
fi

DATABASE_URL="postgres://$PGUSER:$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE?sslmode=disable"

MIGRATIONS_PATH=.

echo "Running migrations..."

# Check if migrate CLI is installed
if ! command -v migrate &> /dev/null
then
    echo "migrate CLI not found. Please install it first:"
    echo "go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
    echo "if not fgound add it to path  :  echo 'export PATH="$PATH:/home/dev/go/bin"' >> ~/.zshrc"
    exit 1
fi

migrate -database "$DATABASE_URL" -path $MIGRATIONS_PATH up

echo "Migrations applied successfully."
