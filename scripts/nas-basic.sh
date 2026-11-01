#!/bin/sh
# Stream via SSH stdin only. No files written, no signals, no elevation.
# Output is private evidence, NOT suitable for automatic model upload.
export LC_ALL=C
printf 'RECOVERY_BASIC_V1\n'
for section in clock kernel identity boot uptime memory swap mounts version tools; do
  printf '\nSECTION:%s\n' "$section"
  case "$section" in
    clock) date -u '+%Y-%m-%dT%H:%M:%SZ';;
    kernel) uname -srm;;
    identity) id;;
    boot) cat /proc/sys/kernel/random/boot_id;;
    uptime) cat /proc/uptime;;
    memory) cat /proc/meminfo;;
    swap) cat /proc/swaps;;
    mounts) cat /proc/mounts;;
    version) cat /etc/VERSION;;
    tools) for t in python3 sha256sum readlink ps; do command -v "$t" || :; done;;
  esac
  printf 'SECTION_RC:%s\n' "$?"
done
printf '\nRECOVERY_BASIC_END\n'
