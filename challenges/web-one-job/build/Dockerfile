FROM php:7.3-fpm-alpine

# 制作者信息
LABEL auther_template="CTF-Archives"

# 安装必要的软件包
RUN apk add --update --no-cache tar nginx mysql mysql-client bash

# 配置mysql
RUN docker-php-source extract && \
    docker-php-ext-install pdo_mysql mysqli && \
    docker-php-source delete && \
    mysql_install_db --user=mysql --datadir=/var/lib/mysql

# 复制nginx+mysql配置文件
COPY ./config/nginx.conf /etc/nginx/nginx.conf
COPY ./config/docker-php-ext-mysqli.ini ./config/docker-php-ext-pdo_mysql.ini /usr/local/etc/php/conf.d/

# 复制web项目源码
COPY src /var/www/html
RUN unzip /var/www/html/www.zip -d /var/www/html/ && \
    chown -R www-data:www-data /var/www/html

# 复制数据库配置文件
COPY ./data/db_lilctf.sql /var/db_lilctf.sql

# 拷贝容器入口点脚本
COPY ./service/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# 配置数据库数据
RUN sh -c 'mysqld_safe &' \
	&& sleep 5s \
    && mysqladmin -uroot password '123456' \ 
    && mysql -e "source /var/db_lilctf.sql;" -uroot -p123456

# 设置shell的工作目录
WORKDIR /var/www/html

EXPOSE 80

# 设置nginx日志保存目录
VOLUME ["/var/log/nginx"]

# 设置容器入口点
ENTRYPOINT [ "/docker-entrypoint.sh" ]
