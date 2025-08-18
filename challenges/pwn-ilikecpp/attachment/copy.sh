#!/bin/bash

IMAGE_TAG=$(echo "ghcr.io/$GITHUB_REPOSITORY/$NAME:latest" | tr '[:upper:]' '[:lower:]')
CONTAINER_ID=$(docker create "$IMAGE_TAG")

docker cp "$CONTAINER_ID:/home/ctf/pwn" "../attachments/"
docker cp "$CONTAINER_ID:/home/ctf/lib/x86_64-linux-gnu/libc.so.6" "../attachments/"
docker cp "$CONTAINER_ID:/home/ctf/lib64/ld-linux-x86-64.so.2" "../attachments/"
docker cp "$CONTAINER_ID:/home/ctf/lib/x86_64-linux-gnu/libstdc++.so.6" "../attachments/"
docker cp "$CONTAINER_ID:/home/ctf/lib/x86_64-linux-gnu/libgcc_s.so.1" "../attachments/"
docker cp "$CONTAINER_ID:/home/ctf/lib/x86_64-linux-gnu/libm.so.6" "../attachments/"

docker rm -v "$CONTAINER_ID" > /dev/null
