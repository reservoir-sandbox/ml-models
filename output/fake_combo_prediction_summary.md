# Reservoir File Analysis Summary

File: `fake_combo`
SHA-256: `2ea78b1006757f67c0dc4a56ea393fc3ed8a39e2d5a327f5fadc842e4f172c92`
Verdict: **SUSPICIOUS**
Suspicious probability: **97.0%**
Risk level: **High**

## Executive Summary

Reservoir classified `fake_combo` as **suspicious** based on static ELF analysis. The strongest static indicators include base64, /bin/bash, /bin/sh, busybox, chmod, chown, cron, curl, /dev/shm, /etc/passwd, /etc/shadow, http:// and 8 more. Imported API evidence includes network: connect, getaddrinfo, socket, process: system, memory: mmap, mprotect.

This analysis is static only: the binary was not executed.

## Key Evidence

Suspicious strings:
- base64
- /bin/bash
- /bin/sh
- busybox
- chmod
- chown
- cron
- curl
- /dev/shm
- /etc/passwd
- /etc/shadow
- http://
- https://
- iptables
- LD_PRELOAD
- netcat/nc
- /proc
- telnet
- /tmp
- wget

Suspicious imports:
- connect
- getaddrinfo
- mmap
- mprotect
- socket
- system

## Technical Snapshot

- File size: 20848 bytes
- ELF detected: True
- Sections: 37
- Segments: 13
- Strings extracted: 221
- Network imports: 3
- Process imports: 1
- Memory imports: 2
- Heuristic score: 0.355

## Notes

This MVP summary is generated from structured static-analysis output. It is intended for quick analyst review and future integration with the Reservoir report UI. The current model was trained on a small synthetic dataset, so the result should not be treated as production malware detection.
