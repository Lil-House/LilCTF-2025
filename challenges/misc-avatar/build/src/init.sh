#!/bin/sh

if [ "$A1CTF_FLAG" ]; then
    export INSERT_FLAG="$A1CTF_FLAG"
    unset A1CTF_FLAG
elif [ "$LILCTF_FLAG" ]; then
    export INSERT_FLAG="$LILCTF_FLAG"
    unset LILCTF_FLAG
elif [ "$GZCTF_FLAG" ]; then
    export INSERT_FLAG="$GZCTF_FLAG"
    unset GZCTF_FLAG
elif [ "$FLAG" ]; then
    export INSERT_FLAG="$FLAG"
    unset FLAG
else
    export INSERT_FLAG="LILCTF{!!!!!_FLAG_ERROR_ASK_ADMIN_!!!!!}"
fi

python gen.py

unset INSERT_FLAG

python serve.py
