#!/bin/sh

if [ "$LILCTF_FLAG" ]; then
    :
elif [ "$A1CTF_FLAG" ]; then
    export LILCTF_FLAG="$A1CTF_FLAG"
    unset A1CTF_FLAG
elif [ "$GZCTF_FLAG" ]; then
    export LILCTF_FLAG="$GZCTF_FLAG"
    unset GZCTF_FLAG
elif [ "$FLAG" ]; then
    export LILCTF_FLAG="$FLAG"
    unset FLAG
else
    export LILCTF_FLAG="LILCTF{!!!!_FLAG_ERROR_ASK_ADMIN_!!!!}"
fi

socat -T10 TCP-LISTEN:70,reuseaddr,fork EXEC:"python3 -u /home/ctf/chall.py",stderr
