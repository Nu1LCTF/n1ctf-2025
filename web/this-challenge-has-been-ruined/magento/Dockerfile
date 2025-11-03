FROM php:8.2-apache

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources

RUN apt update && apt install -y \
    build-essential \
    autoconf \
    pkg-config \
    libcurl4-openssl-dev \
    libxml2-dev \
    libgd-dev \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libicu-dev \
    libonig-dev \
    libssl-dev \
    default-libmysqlclient-dev \
    libsodium-dev \
    libxslt1-dev \
    zlib1g-dev \
    libzip-dev \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-jpeg --with-freetype

RUN docker-php-ext-install \
    bcmath \
    intl \
    curl \
    iconv \
    mbstring \
    xml \
    soap \
    zip \
    sodium \
    pdo_mysql \
    gd \
    xsl \
    sockets

RUN docker-php-ext-install ftp


RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php \
    && php -r "unlink('composer-setup.php');" \
    && mv composer.phar /usr/local/bin/composer


RUN cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini
RUN sed -i 's/memory_limit = .*/memory_limit = 1G/' /usr/local/etc/php/php.ini


WORKDIR /var/www/

# fill your own Magento repo auth keys here
COPY auth.json /root/.composer/auth.json

RUN composer create-project --repository-url=https://repo.magento.com/ magento/project-community-edition:2.4.8 magento

WORKDIR /var/www/magento/

RUN bin/magento setup:install --base-url=http://127.0.0.1/ --db-host=127.0.0.1 --db-name=magento --db-user=magento --db-password=08XXaRHi2R9TfzJi --admin-firstname=Magento --admin-lastname=User --admin-email=user@example.com --admin-user=admin --admin-password=4PvLs2vzAt7XPlfH --language=en_US --currency=USD --timezone=America/Chicago --use-rewrites=1 --search-engine=opensearch --opensearch-host=10.253.253.3 --opensearch-port=9200

RUN a2enmod rewrite && a2enmod headers

COPY Payment.php /var/www/magento/vendor/magento/module-quote/Model/Quote/Payment.php

RUN chown -R www-data:www-data /var/www/magento/var /var/www/magento/pub/ /var/www/magento/generated

COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
