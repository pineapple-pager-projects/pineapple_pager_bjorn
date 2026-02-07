# Telnet server with weak credentials for testing
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    telnetd \
    xinetd \
    && rm -rf /var/lib/apt/lists/*

# Create users with weak passwords
RUN useradd -m -s /bin/bash admin && echo "admin:admin" | chpasswd
RUN useradd -m -s /bin/bash test && echo "test:test" | chpasswd
RUN echo "root:root" | chpasswd

# Configure xinetd for telnet
RUN echo 'service telnet\n\
{\n\
    disable = no\n\
    flags = REUSE\n\
    socket_type = stream\n\
    wait = no\n\
    user = root\n\
    server = /usr/sbin/in.telnetd\n\
    log_on_failure += USERID\n\
}' > /etc/xinetd.d/telnet

EXPOSE 23

CMD ["xinetd", "-dontfork"]
