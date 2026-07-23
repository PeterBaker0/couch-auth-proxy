#!/bin/sh
# One-shot CouchDB bootstrap for the docker-compose harness.
# Waits for /_up, creates system + demo DBs, seeds demo users, and opens
# acldemo membership so couch-auth-proxy can enforce per-doc ACL for those users.
set -eu

COUCH_URL="${COUCH_URL:-http://couchdb:5984}"
AUTH="${COUCH_ADMIN_USER:-admin}:${COUCH_ADMIN_PASSWORD:-password}"

echo "Waiting for CouchDB..."
until curl -sf -u "$AUTH" "$COUCH_URL/_up" >/dev/null; do
  sleep 1
done

echo "Creating databases..."
curl -sf -u "$AUTH" -X PUT "$COUCH_URL/_users" || true
curl -sf -u "$AUTH" -X PUT "$COUCH_URL/_replicator" || true
curl -sf -u "$AUTH" -X PUT "$COUCH_URL/acldemo" || true

create_user() {
  name="$1"
  pass="$2"
  roles="$3"
  id="org.couchdb.user:${name}"
  curl -sf -u "$AUTH" -X PUT "$COUCH_URL/_users/${id}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"${name}\",\"password\":\"${pass}\",\"roles\":${roles},\"type\":\"user\"}" \
    || true
}

create_user alice 'alice-pass' '["readers"]'
create_user bob 'bob-pass' '["writers"]'
create_user carol 'carol-pass' '["readers"]'
create_user dave 'dave-pass' '[]'

# CouchDB 3.x may create DBs with admin-only _security. couch-auth-proxy enforces
# per-doc ACL; Couch membership should allow authenticated app users through.
echo "Opening acldemo membership for demo users/roles..."
curl -sf -u "$AUTH" -X PUT "$COUCH_URL/acldemo/_security" \
  -H 'Content-Type: application/json' \
  -d '{"admins":{"names":[],"roles":["_admin"]},"members":{"names":["alice","bob","carol","dave"],"roles":["readers","writers"]}}'

echo "Couch init complete."
