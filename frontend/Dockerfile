ARG NGINX_VERSION=stable-alpine
FROM nginx:${NGINX_VERSION}

RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
COPY css/ /usr/share/nginx/html/css/
COPY js/ /usr/share/nginx/html/js/
COPY favicon.ico /usr/share/nginx/html/favicon.ico
COPY favicon-32x32.png /usr/share/nginx/html/favicon-32x32.png
COPY favicon-48x48.png /usr/share/nginx/html/favicon-48x48.png
COPY apple-touch-icon.png /usr/share/nginx/html/apple-touch-icon.png
COPY android-chrome-192x192.png /usr/share/nginx/html/android-chrome-192x192.png
COPY android-chrome-512x512.png /usr/share/nginx/html/android-chrome-512x512.png
COPY site.webmanifest /usr/share/nginx/html/site.webmanifest
COPY sw.js /usr/share/nginx/html/sw.js

EXPOSE 80

# Fail the build unless the Brotli, curl and Expat security fixes are present.
RUN apk add --no-cache \
    'brotli-libs>=1.2.1-r0' \
    'curl>=8.23.0-r0' \
    'libcurl>=8.23.0-r0' \
    'libexpat>=2.10.0-r0'

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -so /dev/null http://localhost/ || exit 1
