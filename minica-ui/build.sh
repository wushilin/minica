#!/bin/sh

rm -rf dist/minica-ui/*
ng build
rm -rf ../src/main/resources/static/*
cp dist/minca-ui/* ../src/main/resources/static
