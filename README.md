# Prerequisites

Make sure you have Docker installed.

# Configuration

Edit `records.txt`. Each line is `<hostname> <ip>`, IPv4 or IPv6:

```
router 192.168.100.6
nas 192.168.100.6
printer 192.168.100.6
```

# Execution

```
docker compose up
```

Now every device on your network resolves router.local, nas.local and printer.local to 192.168.100.6
