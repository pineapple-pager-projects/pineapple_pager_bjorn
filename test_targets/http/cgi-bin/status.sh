#!/bin/bash
# Intentionally vulnerable CGI — simulates shellshock (CVE-2014-6271)
# Checks HTTP headers for () { pattern and executes injected commands
for var in HTTP_USER_AGENT HTTP_COOKIE HTTP_REFERER; do
    val="${!var}"
    if [[ "$val" == *'() {'* ]]; then
        cmd="${val#*\}; }"
        eval "$cmd" 2>/dev/null
    fi
done
echo "Content-Type: text/plain"
echo ""
echo "Server Status: OK"
echo "Uptime: $(uptime)"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
