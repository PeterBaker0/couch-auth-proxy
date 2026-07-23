#!/bin/sh
# CouchDB container entrypoint wrapper for couch-auth-proxy compose.
# Copies JWT/local.ini from a read-only mount into Couch's local.d so the
# stock entrypoint can chown without failing on the bind mount.
set -eu
cp /couch-config/local.ini /opt/couchdb/etc/local.d/couch-auth-proxy.ini
exec /docker-entrypoint.sh /opt/couchdb/bin/couchdb
