FROM alpine:3.22

RUN apk add --no-cache syslog-ng \
    && addgroup -S -g 10001 syslog-gateway \
    && adduser -S -D -H -u 10001 -G syslog-gateway syslog-gateway \
    && install -d -o syslog-gateway -g syslog-gateway -m 0700 /run/syslog-ng

COPY docker/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf

USER 10001:10001

EXPOSE 1514/tcp 1514/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD grep -aq syslog-ng /proc/1/cmdline

CMD ["syslog-ng", "--foreground", "--no-caps", "--persist-file", "/tmp/syslog-ng.persist", "--pidfile", "/tmp/syslog-ng.pid", "--control", "/tmp/syslog-ng.ctl"]
