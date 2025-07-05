FROM php:7.4-apache

RUN apt-get update \
 && apt-get install -y git \
 && rm -rf /var/lib/apt/lists/*

RUN rm -rf /var/www/html/* \
 && git clone https://github.com/webpwnized/mutillidae.git /var/www/html \
 && chown -R www-data:www-data /var/www/html \
 && chmod -R 755 /var/www/html

