# RDP Test Target - XRDP on Alpine
# Credentials: admin:admin, root:root

FROM alpine:3.18

# Install XRDP and minimal desktop
RUN apk add --no-cache \
    xrdp \
    xvfb \
    xfce4 \
    xfce4-terminal \
    dbus \
    ttf-freefont \
    sudo \
    openrc

# Create users with weak passwords
RUN adduser -D -s /bin/sh admin && \
    echo "admin:admin" | chpasswd && \
    echo "root:root" | chpasswd && \
    adduser admin wheel && \
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Configure XRDP with proper authentication
RUN mkdir -p /etc/xrdp && \
    echo "[Globals]" > /etc/xrdp/xrdp.ini && \
    echo "ini_version=1" >> /etc/xrdp/xrdp.ini && \
    echo "port=3389" >> /etc/xrdp/xrdp.ini && \
    echo "crypt_level=high" >> /etc/xrdp/xrdp.ini && \
    echo "security_layer=negotiate" >> /etc/xrdp/xrdp.ini && \
    echo "tcp_nodelay=true" >> /etc/xrdp/xrdp.ini && \
    echo "tcp_keepalive=true" >> /etc/xrdp/xrdp.ini && \
    echo "max_bpp=24" >> /etc/xrdp/xrdp.ini && \
    echo "new_cursors=true" >> /etc/xrdp/xrdp.ini && \
    echo "allow_channels=true" >> /etc/xrdp/xrdp.ini && \
    echo "allow_multimon=false" >> /etc/xrdp/xrdp.ini && \
    echo "" >> /etc/xrdp/xrdp.ini && \
    echo "[Channels]" >> /etc/xrdp/xrdp.ini && \
    echo "rdpdr=true" >> /etc/xrdp/xrdp.ini && \
    echo "rdpsnd=true" >> /etc/xrdp/xrdp.ini && \
    echo "drdynvc=true" >> /etc/xrdp/xrdp.ini && \
    echo "cliprdr=true" >> /etc/xrdp/xrdp.ini && \
    echo "rail=false" >> /etc/xrdp/xrdp.ini && \
    echo "" >> /etc/xrdp/xrdp.ini && \
    echo "[Xvnc]" >> /etc/xrdp/xrdp.ini && \
    echo "name=Xvnc" >> /etc/xrdp/xrdp.ini && \
    echo "lib=libvnc.so" >> /etc/xrdp/xrdp.ini && \
    echo "ip=127.0.0.1" >> /etc/xrdp/xrdp.ini && \
    echo "port=-1" >> /etc/xrdp/xrdp.ini && \
    echo "username=ask" >> /etc/xrdp/xrdp.ini && \
    echo "password=ask" >> /etc/xrdp/xrdp.ini

# Configure sesman - uses PAM for proper authentication
RUN echo "[Globals]" > /etc/xrdp/sesman.ini && \
    echo "ListenAddress=127.0.0.1" >> /etc/xrdp/sesman.ini && \
    echo "ListenPort=3350" >> /etc/xrdp/sesman.ini && \
    echo "EnableUserWindowManager=true" >> /etc/xrdp/sesman.ini && \
    echo "UserWindowManager=startwm.sh" >> /etc/xrdp/sesman.ini && \
    echo "DefaultWindowManager=startwm.sh" >> /etc/xrdp/sesman.ini && \
    echo "" >> /etc/xrdp/sesman.ini && \
    echo "[Security]" >> /etc/xrdp/sesman.ini && \
    echo "AllowRootLogin=true" >> /etc/xrdp/sesman.ini && \
    echo "MaxLoginRetry=3" >> /etc/xrdp/sesman.ini && \
    echo "TerminalServerUsers=users" >> /etc/xrdp/sesman.ini && \
    echo "TerminalServerAdmins=wheel" >> /etc/xrdp/sesman.ini && \
    echo "" >> /etc/xrdp/sesman.ini && \
    echo "[Sessions]" >> /etc/xrdp/sesman.ini && \
    echo "X11DisplayOffset=10" >> /etc/xrdp/sesman.ini && \
    echo "MaxSessions=10" >> /etc/xrdp/sesman.ini && \
    echo "" >> /etc/xrdp/sesman.ini && \
    echo "[Xvnc]" >> /etc/xrdp/sesman.ini && \
    echo "param=-geometry" >> /etc/xrdp/sesman.ini && \
    echo "param=1024x768" >> /etc/xrdp/sesman.ini && \
    echo "param=-depth" >> /etc/xrdp/sesman.ini && \
    echo "param=24" >> /etc/xrdp/sesman.ini

# Create startup script
RUN echo '#!/bin/sh' > /start.sh && \
    echo 'mkdir -p /var/run/xrdp' >> /start.sh && \
    echo 'xrdp-keygen xrdp auto 2>/dev/null || true' >> /start.sh && \
    echo 'xrdp-sesman &' >> /start.sh && \
    echo 'exec xrdp --nodaemon' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 3389

CMD ["/start.sh"]
