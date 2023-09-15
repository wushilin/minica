#!/bin/sh
#
gradle bootJar
mkdir -p ca.localonly/CAs
java -jar build/libs/minica-0.0.1-SNAPSHOT.jar  --spring.config.location=./application.properties
