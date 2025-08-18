#!/bin/bash

rm -f /docker-entrypoint.sh

mysqld_safe &

mysql_ready() {
	mysqladmin ping --socket=/run/mysqld/mysqld.sock --user=root --password=root > /dev/null 2>&1
}

while !(mysql_ready)
do
	echo "waiting for mysql ..."
	sleep 3
done


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

echo "Run:insert into flag values('flag','$INSERT_FLAG');"

# 将FLAG写入文件 请根据需要修改
# echo $INSERT_FLAG | tee /home/$user/flag /flag


mysql -u root -p123456 -e "
USE lilctf;
insert into pre_a_flag values('2','$INSERT_FLAG');
"

php-fpm & nginx &

echo "Running..."

tail -F /var/log/nginx/access.log /var/log/nginx/error.log