# DNSTrace
A Python tool that performs a continuous traceroute using DNS packets, displaying real-time statistics in a terminal UI similar to mtr.

## Features
- Continuous probing like mtr, updating stats over time.
- Uses DNS packets over UDP for tracing.
- Curses-based UI for live display.
- Handles timeouts by continuing to next hops and retrying in cycles.
- Configurable via command-line arguments.

## Requirements
- Python 3.x
- Scapy (install via `pip install scapy`)
- Run with sudo for raw socket access.

## Installation
Just Clone the repository

## Usage
./dnstrace.py [-h] [--interval INTERVAL] [--max-hops MAX_HOPS] dst_ip domain

## License
MIT License (see LICENSE file).
