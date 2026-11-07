# docker build -t neora-web .   (see "Web app" in the root README.md for the full docker run command)
FROM nginx:1.27-alpine
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html robots.txt /var/www/neora/
COPY css /var/www/neora/css
COPY js /var/www/neora/js
COPY config /var/www/neora/config
