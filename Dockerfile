FROM nginx:alpine

LABEL maintainer="Sandeep Wawdane <contact@thecybersandeep.com>"
LABEL org.opencontainers.image.authors="Sandeep Wawdane (original creator); 0x0806 (enhancements)"
LABEL org.opencontainers.image.source="https://github.com/0x0806/adbauditor"
LABEL description="ADB Auditor - Professional Android Security Auditing Platform"
LABEL version="2.1.1"

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY . /usr/share/nginx/html/

RUN cd /usr/share/nginx/html && rm -rf Dockerfile docker-compose.yml nginx.conf .dockerignore .git .github \
    README.md CHANGELOG.md CNAME docs tests scripts package.json 2>/dev/null || true

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
