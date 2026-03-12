#!/bin/bash
# Intentionally vulnerable CGI — simulates shellshock (CVE-2014-6271)
for var in HTTP_USER_AGENT HTTP_COOKIE HTTP_REFERER; do
    val="${!var}"
    if [[ "$val" == *'() {'* ]]; then
        cmd="${val#*\}; }"
        eval "$cmd" 2>/dev/null
    fi
done
echo "Content-Type: text/plain"
echo ""
echo "CGI Test Script"
echo "Request Method: $REQUEST_METHOD"
echo "Query String: $QUERY_STRING"
echo "User Agent: $HTTP_USER_AGENT"
