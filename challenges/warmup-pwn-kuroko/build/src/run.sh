#!/bin/sh

echo -e 'Shirai Kuroko'
echo -e 'Input your code (end with "EOF")\n'

echo "" > /home/ctf/exp.krk

IFS=''
while read -r -t 30 input; do
    if [ "$input" = "EOF" ]; then
        break
    fi
    echo "$input" >> /home/ctf/exp.krk
done

/chroot --userspec=1000:1000 /home/ctf ./kuroko /exp.krk
