#!/bin/sh

docker build -t thecuriousgeek/vault:latest .
docker rmi `docker images -qa -f 'dangling=true'` >/dev/null 2>&1
