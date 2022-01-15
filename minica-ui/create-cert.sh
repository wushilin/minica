#!/bin/sh

curl -H "Content-Type: application/json"  -X PUT --data @create-cert.json http://localhost:4200/ca/bdd82da5-2148-4255-b20e-58be52d16f0e/new
