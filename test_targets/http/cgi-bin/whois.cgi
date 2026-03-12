#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><body><h1>WHOIS Lookup</h1>"
echo "<form method='GET'><input name='domain'><button>Lookup</button></form>"
echo "<pre>"
if [ -n "$QUERY_STRING" ]; then
    echo "Query: $QUERY_STRING"
fi
echo "</pre></body></html>"
