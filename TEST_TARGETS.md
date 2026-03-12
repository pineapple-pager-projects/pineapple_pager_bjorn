# Test Targets - Vulnerable Test Appliance

A **deliberately vulnerable Docker environment** designed to test the effectiveness of Loki's attack modules. It provides a safe, isolated set of target services with weak credentials.

**Important:** This environment runs on your computer (not on the Pager). The Pager runs Loki, which scans the network and attacks these vulnerable containers.

## What This Tests

- Network scanning and host discovery
- Service enumeration (SSH, FTP, SMB, Telnet, RDP, MySQL, HTTP)
- Credential brute-forcing with dictionary attacks
- File exfiltration from compromised services
- Database data theft from MySQL
- Anonymous/guest access detection

## Quick Start

```bash
cd test_targets

# Start all services
docker-compose up -d

# Check services are running
docker-compose ps

# Stop all services
docker-compose down
```

## Test Services & Credentials

All services share a single IP (**172.16.52.228**) so Loki discovers one host with all ports open.

| Service | Port | Credentials | Notes |
|---------|------|-------------|-------|
| SSH | 22 | admin:admin, test:test, root:root | Minimal Alpine container |
| FTP | 21 | admin:admin | |
| SMB | 445 | public: anonymous, private: admin:admin | |
| MySQL | 3306 | root:root, admin:admin | |
| Telnet | 23 | admin:admin, test:test, root:root | Minimal Alpine container |
| HTTP | 80, 8080 | N/A | |
| RDP | 3389 | admin:admin, root:root | NLA mock server |

All services run on **172.16.52.0/24** - the same network as the Pager (172.16.52.1).

The SSH and Telnet containers include test files for file stealing validation (`.env`, `.flag`, `.bashrc`, etc.).

## Expected Results

After running Loki against test targets, you should see:
- **netkb.csv** - All 7 targets discovered with open ports
- **ssh.csv, ftp.csv, smb.csv, telnet.csv, sql.csv, rdp.csv** - Cracked credentials
- **datastolen/** - Exfiltrated files and database dumps

## Troubleshooting

### Containers not starting
```bash
docker-compose logs [service-name]
```

### MySQL connection refused
Wait 30-60 seconds after `docker-compose up` for MySQL to initialize.
