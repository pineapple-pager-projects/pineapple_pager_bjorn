#!/bin/bash
echo "Content-Type: text/plain"
echo ""
echo "Finger service"
echo "User: ${QUERY_STRING:-root}"
echo "Login: root    Name: System Administrator"
echo "Directory: /root    Shell: /bin/bash"
