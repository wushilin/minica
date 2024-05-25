#!/bin/sh

curl -H "X-XSRF-TOKEN: 123" -H "Cookie: XSRF-TOKEN=123;" -u "admin:password" -vvvv -H "Content-Type: application/json"  -X PUT --data @import-ca.json http://localhost:4200/ca/import
