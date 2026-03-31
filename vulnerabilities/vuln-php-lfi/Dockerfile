FROM php:8.2-cli-alpine

WORKDIR /var/www/html

COPY index.php ./
RUN mkdir -p /var/www/html/secret && echo "flag{lfi_master_found}" > /var/www/html/secret/flag.txt

# Create an unprivileged user
RUN adduser -D -u 1000 phpuser
USER phpuser

EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/var/www/html"]
