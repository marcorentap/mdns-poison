# Prerequisites

Make sure you have Docker installed.

# Configuration

```
router 192.168.100.6
nas 192.168.100.6
printer 192.168.100.6
*.dev 192.168.100.6
```

`*.dev` matches `anything.dev.local` (query-only, not announced).

# Execution

```
docker compose up
```

Now every device on your network resolves router.local, nas.local and printer.local to 192.168.100.6. If a `*` record is present, all other records are ignored and every `*.local` resolves to its IP.
