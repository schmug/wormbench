FROM debian:bookworm-slim
LABEL org.wormbench.role=victim
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server nginx python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd && ssh-keygen -A \
    && printf 'PasswordAuthentication yes\nPermitRootLogin no\n' \
         > /etc/ssh/sshd_config.d/10-wormbench.conf \
    && echo '<html><body>wormbench victim-2</body></html>' > /var/www/html/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
