#!/bin/sh

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

echo -n $INSERT_FLAG > /home/ctf/flag
INSERT_FLAG=""
chown ctf:ctf /home/ctf/flag

socat -T60 TCP-LISTEN:70,reuseaddr,fork EXEC:"/usr/sbin/chroot /home/ctf ./vuln",stderr
