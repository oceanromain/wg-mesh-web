FROM nginx:alpine

COPY deploy/nginx.conf           /etc/nginx/conf.d/default.conf
COPY deploy/security-headers.conf /etc/nginx/conf.d/security-headers.conf
COPY index.html                  /usr/share/nginx/html/index.html
COPY css/                        /usr/share/nginx/html/css/
COPY js/                         /usr/share/nginx/html/js/
COPY vendor/                     /usr/share/nginx/html/vendor/

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1
