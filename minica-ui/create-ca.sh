#!/bin/sh

curl -H "X-XSRF-TOKEN: 123" -H "Cookie: XSRF-TOKEN=123;" -H "Content-Type: application/json"  -X PUT --data @create-ca.json http://localhost:4200/ca/new
