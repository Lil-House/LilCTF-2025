#!/bin/sh

# Get the user
user=$(ls /home)

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

echo -n $INSERT_FLAG > /flag
INSERT_FLAG=""

# 控制flag和项目源码的权限
chmod 744 /flag
chmod 740 /app/*

# 运行jar程序文件
java -jar /app/app.jar