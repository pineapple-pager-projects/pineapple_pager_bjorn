# Minimal SSH server for testing - Alpine-based (~100 files vs 22k)
FROM alpine:3.19

# Install openssh and bash
RUN apk add --no-cache openssh bash

# Generate host keys
RUN ssh-keygen -A

# Create test users with weak passwords
RUN adduser -D -s /bin/bash admin && echo "admin:admin" | chpasswd
RUN adduser -D -s /bin/bash test && echo "test:test" | chpasswd
RUN echo "root:root" | chpasswd

# Enable password authentication and root login
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Add test files for file stealing
RUN mkdir -p /root /home/admin /tmp
RUN echo "FLAG{ssh_pwned}" > /root/secret.flag
RUN echo "admin_password=supersecret456" > /home/admin/.env
RUN echo "ssh_test_credentials" > /tmp/hack.txt
RUN echo "api_key=sk-1234567890abcdef" > /home/admin/.config

# Create .bashrc files (common steal target)
RUN echo "export PATH=/usr/local/bin:\$PATH" > /root/.bashrc
RUN echo "export PATH=/usr/local/bin:\$PATH" > /home/admin/.bashrc
RUN chown admin:admin /home/admin/.bashrc /home/admin/.env /home/admin/.config

EXPOSE 22

# Run sshd in foreground
CMD ["/usr/sbin/sshd", "-D", "-e"]
