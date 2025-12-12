#!/usr/bin/env python3
"""
Live DNS Traceroute Tool

This script performs a continuous traceroute using DNS packets, similar to mtr,
displaying real-time statistics in a curses-based UI.

Usage:
    sudo python3 dnstrace.py <destination_ip> <domain> [options]

Requires scapy and running with sudo for raw sockets.
"""

import argparse
import curses
import time
import signal
from collections import deque
from statistics import mean, stdev
from scapy.all import IP, UDP, DNS, ICMP, DNSQR, sr1, RandShort, get_if_addr, conf

stop_running = False
max_reached_hop = 0
target_hop = 30

def sigint_handler(sig, frame):
    """Handle SIGINT for graceful shutdown."""
    global stop_running
    stop_running = True

signal.signal(signal.SIGINT, sigint_handler)

class Hop:
    """Class to store statistics for each hop."""
    def __init__(self):
        self.sent = 0
        self.recv = 0
        self.rtts = deque(maxlen=500)
        self.last = 0.0
        self.addr = "*"

def send_probe(ttl, dst_ip, domain):
    """Send a probe packet to the given TTL and handle the reply."""
    global max_reached_hop, target_hop

    sport = RandShort()
    pkt = IP(dst=dst_ip, ttl=ttl) / UDP(dport=53, sport=sport) / DNS(rd=1, qd=DNSQR(qname=domain))
    pkt.sent_time = time.time()

    reply = sr1(pkt, timeout=1.0, verbose=0)
    hop = hops[ttl]
    hop.sent += 1

    if reply:
        rtt = (reply.time - pkt.sent_time) * 1000
        hop.recv += 1
        hop.last = rtt
        hop.rtts.append(rtt)
        if hop.addr == "*":
            hop.addr = reply.src

        # Update highest reached hop
        if ttl > max_reached_hop:
            max_reached_hop = ttl

        # Set target hop when destination answers
        if reply.src == dst_ip:
            if reply.haslayer(DNS) or (reply.haslayer(ICMP) and reply[ICMP].type == 3):
                target_hop = ttl

def main(stdscr, args):
    """Main function to run the curses UI and probing loop."""
    global stop_running, max_reached_hop, target_hop
    curses.curs_set(0)
    stdscr.nodelay(True)
    my_ip = get_if_addr(conf.iface) or "?.?.?.?"

    global hops
    hops = [Hop() for _ in range(args.max_hops + 1)]
    target_hop = args.max_hops

    ttl = 1
    next_send = time.time()

    while not stop_running:
        now = time.time()

        # Send packets at the specified interval
        if now >= next_send:
            send_probe(ttl, args.dst_ip, args.domain)
            next_send = now + args.interval
            ttl = 1 if ttl >= target_hop else ttl + 1

        # Draw the UI
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        title = f"Live DNS Traceroute → {args.dst_ip} ({args.domain}) from {my_ip}"
        stdscr.addstr(0, 0, title[:w-1], curses.A_BOLD)
        stdscr.addstr(2, 0, "Hop Loss%   Pkts    Last     Avg    Best   Worst  StDev  Host", curses.A_BOLD)

        # Show hops up to max reached + 2
        visible_hops = min(h - 4, max_reached_hop + 2)
        for i in range(1, visible_hops + 1):
            hop = hops[i]
            if hop.sent == 0 and i > max_reached_hop:
                continue

            if hop.sent == 0:
                line = f"{i:2d}   ---     ---      *       *      *      *      *   {hop.addr}"
            else:
                loss = 100.0 * (hop.sent - hop.recv) / hop.sent
                if not hop.rtts:
                    last_s = "*     "
                    avg_s = "*     "
                    best_s = "*    "
                    worst_s = "*     "
                    sdev_s = "*    "
                else:
                    last_s = f"{hop.last:6.2f}"
                    avg = mean(hop.rtts)
                    avg_s = f"{avg:6.2f}"
                    best = min(hop.rtts)
                    best_s = f"{best:5.2f}"
                    worst = max(hop.rtts)
                    worst_s = f"{worst:5.2f}"
                    sdev = stdev(hop.rtts) if len(hop.rtts) >= 2 else 0.0
                    sdev_s = f"{sdev:5.2f}"

                line = f"{i:2d} {loss:5.1f}%  {hop.sent:4d}  {last_s}  {avg_s}  {best_s}  {worst_s}  {sdev_s}  {hop.addr}"

            stdscr.addstr(i + 2, 0, line[:w-1])

        footer = "Press q or Ctrl+C to quit"
        stdscr.addstr(h-1, 0, footer, curses.A_REVERSE)
        stdscr.refresh()

        if stdscr.getch() in (ord('q'), ord('Q')):
            stop_running = True

        time.sleep(0.01)

    stdscr.nodelay(False)
    stdscr.addstr(h-1, 0, "Finished – press any key to exit...", curses.A_REVERSE)
    stdscr.getch()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Live DNS Traceroute Tool - mtr-like UI with DNS packets."
    )
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("domain", help="Domain name for DNS query")
    parser.add_argument("--interval", type=float, default=0.1, help="Interval between probes (seconds, default: 0.1)")
    parser.add_argument("--max-hops", type=int, default=30, help="Maximum number of hops (default: 30)")

    args = parser.parse_args()

    try:
        curses.wrapper(lambda stdscr: main(stdscr, args))
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: This script requires sudo for raw socket access.")
