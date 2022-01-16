#!/bin/sh

curl -u "admin:password" -vvvv -H "Content-Type: application/json"  -X PUT --data @import-ca.json http://localhost:4200/ca/import
