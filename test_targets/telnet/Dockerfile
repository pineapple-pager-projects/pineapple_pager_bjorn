# Minimal Telnet server for testing - Alpine-based (~50 files vs 23k)
FROM alpine:3.19

# Install only busybox-extras (includes telnetd) and bash for shell
RUN apk add --no-cache busybox-extras bash

# Create test users with weak passwords
RUN adduser -D -s /bin/bash admin && echo "admin:admin" | chpasswd
RUN adduser -D -s /bin/bash test && echo "test:test" | chpasswd
RUN echo "root:root" | chpasswd

# Add test files for file stealing
RUN mkdir -p /root /home/admin /tmp
RUN echo "FLAG{telnet_pwned}" > /root/secret.flag
RUN echo "admin_password=supersecret123" > /home/admin/.env
RUN echo "test_credentials" > /tmp/hack.txt
RUN echo "database_url=mysql://admin:admin@localhost/db" > /home/admin/.config

# Create .bashrc files (common steal target)
RUN echo "export PATH=/usr/local/bin:\$PATH" > /root/.bashrc
RUN echo "export PATH=/usr/local/bin:\$PATH" > /home/admin/.bashrc
RUN chown admin:admin /home/admin/.bashrc /home/admin/.env /home/admin/.config

EXPOSE 23

# Run telnetd in foreground
CMD ["telnetd", "-F"]
