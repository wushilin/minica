#!/bin/sh

curl -H "Content-Type: application/json"  -X PUT --data @create-ca.json http://localhost:4200/ca/new
