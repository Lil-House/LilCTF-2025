#!/bin/bash

# Check the environment variables for the flag and assign to INSERT_FLAG

if [ "$A1CTF_FLAG" ]; then
    INSERT_FLAG="$A1CTF_FLAG"
    unset A1CTF_FLAG
elif [ "$LILCTF_FLAG" ]; then
    INSERT_FLAG="$LILCTF_FLAG"
    unset LILCTF_FLAG
elif [ "$GZCTF_FLAG" ]; then
    INSERT_FLAG="$GZCTF_FLAG"
    unset GZCTF_FLAG
elif [ "$FLAG" ]; then
    INSERT_FLAG="$FLAG"
    unset FLAG
else
    INSERT_FLAG="LILCTF{!!!!_FLAG_ERROR_ASK_ADMIN_!!!!}"
fi

echo -n $INSERT_FLAG > /ctf/flag.txt

FLAG_LENGTH=${#INSERT_FLAG}
HALF_LENGTH=$((FLAG_LENGTH / 2))
FLAG_SUFFIX=${INSERT_FLAG:$HALF_LENGTH}


HEX_FLAG=""
for (( i=0; i<${#FLAG_SUFFIX}; i++ )); do
    char="${FLAG_SUFFIX:$i:1}"
    hex=$(printf "%02x" "'$char")
    HEX_FLAG="$HEX_FLAG$hex"
done

sed -i "s/746869735f69735f766572795f6c6f6e675f646174615f77686963685f6e6565645f676574/$HEX_FLAG/g" /ctf/challenge.yml


FLAG_PREFIX=${INSERT_FLAG:7:4}
HEX_PREFIX=""
for (( i=0; i<${#FLAG_PREFIX}; i++ )); do
    char="${FLAG_PREFIX:$i:1}"
    hex=$(printf "%02x" "'$char")
    HEX_PREFIX="$HEX_PREFIX$hex"
done


XOR_KEY="key_$HEX_PREFIX"


sed -i "s/shenghuo2/$XOR_KEY/g" /ctf/contracts/Example.sol


INSERT_FLAG=""
FLAG_SUFFIX=""
HEX_FLAG=""
FLAG_PREFIX=""
HEX_PREFIX=""
XOR_KEY=""


exec /entrypoint.sh