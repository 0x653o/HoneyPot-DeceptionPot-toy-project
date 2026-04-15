FROM php:8.2-cli-alpine

WORKDIR /var/www/html

# Install pdo_sqlite
RUN apk add --no-cache sqlite-dev \
    && docker-php-ext-install pdo_sqlite

COPY index.php ./

# Create an unprivileged user
RUN adduser -D -u 1000 phpuser
USER phpuser

EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]
