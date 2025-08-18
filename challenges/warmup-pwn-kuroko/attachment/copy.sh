#!/bin/bash

IMAGE_TAG=$(echo "ghcr.io/$GITHUB_REPOSITORY/$NAME:latest" | tr '[:upper:]' '[:lower:]')
CONTAINER_ID=$(docker create "$IMAGE_TAG")

mkdir -p ../attachments/source
mkdir -p ../attachments/artifacts

cp -r Dockerfile src ../attachments/source/

docker cp "$CONTAINER_ID:/home/ctf/kuroko" "../attachments/artifacts/"
docker cp "$CONTAINER_ID:/home/ctf/lib/x86_64-linux-gnu/libc.so.6" "../attachments/artifacts/"
docker cp "$CONTAINER_ID:/home/ctf/lib64/ld-linux-x86-64.so.2" "../attachments/artifacts/"

docker rm -v "$CONTAINER_ID" > /dev/null
