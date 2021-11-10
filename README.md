# DnsSpoofer
DNS spoofing daemon for Linux that listens on the DNS port for any A record request (e.g. foo.com) returns a fixed, hard coded address.
The is intented to be DNS cache server only and for vlaidating and authorizing server.

## Target to Achieve:
 - Linux pthread daemon
 - Listens to specific port (UDP dst port)
 - Checks if it is a DNS record
 - For the right request, returns fixed DNS respeonse

## Assumptions:
  - Runs for IPv4 only.
  - does not uses encrypted TLS or SSL.
  - Should only intercept `foo.com`.
  - Bypasses for other requests
  - If the DNS response is received drop the same.
  - Periodic stats (optional)

## requirements
  - error handle
  - comments
  - unit tests
  - reference to online or PDF material in use

Note: DNS non authorative request are processed as DNS cache server.
