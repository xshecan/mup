#!/usr/bin/env python3
"""Render the MUP documentation diagrams as light and dark SVG files.

Run from any directory: python3 .docs/render_diagrams.py
The script uses only the Python standard library. It writes
.docs/images/<name>-light.svg and .docs/images/<name>-dark.svg.

The diagrams follow one rule for color. Everything is neutral ink, and amber
marks only the peer token, or a line that carries it. Red marks an unhealthy
path. The images have no background, so they sit on the page in both themes.
"""

import hashlib
import math
import re
import struct
from pathlib import Path
from xml.sax.saxutils import escape

OUTPUT = Path(__file__).resolve().parent / "images"

SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"

# The images are 800 wide, so they show at full size in a GitHub README column.
WIDTH = 800
BODY = 14
NAME = 16

THEMES = {
    "light": {
        "text": "#111827", "secondary": "#4b5565", "muted": "#6b7487",
        "hair": "#d9dde4", "raised": "#f5f7fa",
        "accent": "#b45309", "accent_soft": "#fdf3e3", "negative": "#dc2626",
    },
    "dark": {
        "text": "#eef0f5", "secondary": "#a3a9b8", "muted": "#7a8296",
        "hair": "#2a2f3a", "raised": "#161a22",
        "accent": "#f0a742", "accent_soft": "#33250f", "negative": "#e5484d",
    },
}

NO_TOKEN = "00 00 00"
TOKEN = "00 00 11"


def color(role):
    return role if role == "none" else f"%%{role}%%"


def number(value):
    text = f"{value:.1f}"
    return text[:-2] if text.endswith(".0") else text


class Diagram:
    def __init__(self, name, height, title, description):
        self.name = name
        self.height = height
        self.title = title
        self.description = description
        self.parts = []

    def rect(self, x, y, w, h, fill="none", stroke="hair", radius=8, stroke_width=1):
        attributes = (
            f'x="{number(x)}" y="{number(y)}" width="{number(w)}" height="{number(h)}" '
            f'rx="{number(radius)}" fill="{color(fill)}"'
        )
        if stroke != "none":
            attributes += f' stroke="{color(stroke)}" stroke-width="{number(stroke_width)}"'
        self.parts.append(f"<rect {attributes}/>")

    def spans(self, x, y, spans, anchor="start"):
        """Write text from (content, fill, mono, weight) spans on one line."""
        inner = "".join(
            f'<tspan class="{"m" if mono else "s"}" fill="{color(fill)}" font-weight="{weight}">{escape(content)}</tspan>'
            for content, fill, mono, weight in spans
        )
        self.parts.append(
            f'<text x="{number(x)}" y="{number(y)}" font-size="{BODY}" text-anchor="{anchor}">{inner}</text>'
        )

    def text(self, x, y, content, fill="text", size=BODY, weight=400, anchor="start", mono=False):
        self.parts.append(
            f'<text class="{"m" if mono else "s"}" x="{number(x)}" y="{number(y)}" font-size="{size}" '
            f'font-weight="{weight}" fill="{color(fill)}" text-anchor="{anchor}">{escape(content)}</text>'
        )

    def name_text(self, x, y, content, anchor="start", fill="text"):
        self.text(x, y, content, fill=fill, size=NAME, weight=500, anchor=anchor)

    def line(self, x1, y1, x2, y2, stroke="hair", stroke_width=1, dash=None):
        dash_attribute = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<path d="M{number(x1)} {number(y1)} L{number(x2)} {number(y2)}" fill="none" '
            f'stroke="{color(stroke)}" stroke-width="{number(stroke_width)}"{dash_attribute}/>'
        )

    def head(self, x, y, angle, fill, size=8):
        back_x = x - size * math.cos(angle)
        back_y = y - size * math.sin(angle)
        spread_x = size * 0.5 * math.sin(angle)
        spread_y = size * 0.5 * math.cos(angle)
        points = [(x, y), (back_x + spread_x, back_y - spread_y), (back_x - spread_x, back_y + spread_y)]
        text = " ".join(f"{number(px)},{number(py)}" for px, py in points)
        self.parts.append(f'<polygon points="{text}" fill="{color(fill)}"/>')

    def arrow(self, x1, y1, x2, y2, stroke="secondary", stroke_width=1.5, dash=None, both=False):
        angle = math.atan2(y2 - y1, x2 - x1)
        inset = 6
        start_x = x1 + inset * math.cos(angle) if both else x1
        start_y = y1 + inset * math.sin(angle) if both else y1
        self.line(start_x, start_y, x2 - inset * math.cos(angle), y2 - inset * math.sin(angle), stroke, stroke_width, dash)
        self.head(x2, y2, angle, stroke)
        if both:
            self.head(x1, y1, angle + math.pi, stroke)

    def elbow(self, points, stroke="secondary", stroke_width=1.5):
        (px, py), (x, y) = points[-2], points[-1]
        angle = math.atan2(y - py, x - px)
        trimmed = points[:-1] + [(x - 6 * math.cos(angle), y - 6 * math.sin(angle))]
        d = "M" + " L".join(f"{number(a)} {number(b)}" for a, b in trimmed)
        self.parts.append(f'<path d="{d}" fill="none" stroke="{color(stroke)}" stroke-width="{number(stroke_width)}"/>')
        self.head(x, y, angle, stroke)

    def bytes_value(self, x, y, value):
        """Write WireGuard bytes 1 to 3, centered on x. Amber means a peer token."""
        live = value != NO_TOKEN
        if live:
            self.rect(x - 40, y - 15, 80, 21, fill="accent_soft", stroke="none", radius=4)
        self.text(x, y, value, fill="accent" if live else "muted", weight=500 if live else 400, anchor="middle", mono=True)

    def render(self, theme):
        palette = THEMES[theme]
        body = "\n".join(self.parts)
        body = re.sub(r"%%(\w+)%%", lambda match: palette[match.group(1)], body)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{self.height}" '
            f'viewBox="0 0 {WIDTH} {self.height}" role="img" aria-labelledby="title desc" xml:space="preserve">\n'
            f'<title id="title">{escape(self.title)}</title>\n'
            f'<desc id="desc">{escape(self.description)}</desc>\n'
            f"<style>.s{{font-family:{SANS}}}.m{{font-family:{MONO};white-space:pre}}</style>\n"
            f"{body}\n</svg>\n"
        )


def internet_checksum(data):
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def build_packet(source, source_port, destination, destination_port, wireguard):
    """Build an IPv4 and UDP packet with valid checksums."""
    length = 20 + 8 + len(wireguard)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, 0x1c46, 0x4000, 64, 17, 0, source, destination)
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(wireguard), 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 17, 8 + len(wireguard))
    checksum = internet_checksum(pseudo + udp + wireguard) or 0xffff
    udp = udp[:6] + struct.pack("!H", checksum)
    return header + udp + wireguard


def keepalive_packets():
    """Return one WireGuard keepalive from a peer, and the same packet on a UDP path.

    The receiver index, counter, and tag are example values, and the peer token
    is 17. protocol.RewritePeerToken and protocol.RewriteUDP turn the first
    packet into the second, byte for byte.
    """
    receiver = bytes.fromhex("c2913f7a")
    counter = struct.pack("<Q", 0x2b01)
    tag = hashlib.sha256(b"mup example keepalive").digest()[:16]
    peer = bytes([198, 51, 100, 44])
    client = bytes([192, 0, 2, 10])
    server = bytes([203, 0, 113, 5])
    before = build_packet(peer, 41000, client, 51820, bytes([4, 0, 0, 0]) + receiver + counter + tag)
    after = build_packet(client, 51820, server, 5000, bytes([4, 0, 0, 17]) + receiver + counter + tag)
    return before, after


def packet():
    before, after = keepalive_packets()
    d = Diagram(
        "packet", 324, "One WireGuard packet before and after a MUP rewrite",
        "A hexdump of a 60-byte WireGuard keepalive from a peer, and the same packet on the wire after the "
        "MUP client rewrites it. Only the addresses, ports, checksums, and the three peer token bytes change.",
    )
    token_columns = range(13, 16)

    def column_x(column):
        return 56 + column * 26 + (8 if column >= 8 else 0)

    def dump(top, title, addresses, data, other, notes, live):
        d.name_text(0, top + 16, title)
        d.text(WIDTH, top + 16, addresses, fill="muted", anchor="end", mono=True)
        for row, note in enumerate(notes):
            y = top + 48 + row * 24
            d.text(0, y, f"{row * 16:04x}", fill="muted", mono=True)
            if row == 1:
                x = column_x(token_columns[0]) - 5
                if live:
                    d.rect(x, y - 15, 3 * 26 + 1, 21, fill="accent_soft", stroke="none", radius=4)
                else:
                    d.rect(x, y - 15, 3 * 26 + 1, 21)
            for column in range(16):
                index = row * 16 + column
                if index >= len(data):
                    break
                is_token = row == 1 and column in token_columns
                if live and is_token:
                    fill, weight = "accent", 500
                elif is_token:
                    fill, weight = "text", 400
                elif data[index] != other[index]:
                    fill, weight = "text", 500
                else:
                    fill, weight = "muted", 400
                d.text(column_x(column), y, f"{data[index]:02x}", fill=fill, weight=weight, mono=True)
            d.text(496, y, note, fill="secondary")

    dump(0, "From the peer", "198.51.100.44:41000 → 192.0.2.10:51820", before, after, [
        "IPv4 header, source address",
        "destination, UDP header, type, zeros",
        "receiver index, counter, tag",
        "authentication tag",
    ], live=False)
    dump(144, "On the wire", "192.0.2.10:51820 → 203.0.113.5:5000", after, before, [
        "checksum, source address",
        "destination, ports, checksum, token",
        "no change",
        "no change",
    ], live=True)

    y = 316
    d.rect(column_x(0) - 5, y - 15, 3 * 26 + 1, 21, fill="accent_soft", stroke="none", radius=4)
    for column, value in enumerate(TOKEN.split()):
        d.text(column_x(column), y, value, fill="accent", weight=500, mono=True)
    d.text(144, y, "peer token", fill="secondary")
    d.text(232, y, "c0", weight=500, mono=True)
    d.text(256, y, "changed", fill="secondary")
    d.text(328, y, "7a", fill="muted", mono=True)
    d.text(352, y, "no change", fill="secondary")
    d.text(WIDTH, y, "60 bytes before, 60 bytes after", fill="secondary", anchor="end")
    return d


def overview():
    d = Diagram(
        "overview", 212, "MUP topology",
        "WireGuard peers send to a MUP client. The client sends each packet over one or more UDP or ICMP "
        "paths to a MUP server, which forwards it to one WireGuard target. The reserved WireGuard bytes hold "
        "a peer token only between the client and the server.",
    )
    top, bottom = 32, 160
    d.bytes_value(104, 16, NO_TOKEN)
    d.bytes_value(400, 16, TOKEN)
    d.bytes_value(680, 16, NO_TOKEN)

    for y, name in zip((60, 100, 140), ("peer A", "peer B", "peer C")):
        d.text(0, y + 5, name)
        d.arrow(64, y, 144, y, both=True)

    for x, width, name, detail in ((144, 128, "MUP client", "TCX program"), (528, 128, "MUP server", "TCX program")):
        d.rect(x, top, width, bottom - top, fill="raised")
        d.name_text(x + width / 2, 92, name, anchor="middle")
        d.text(x + width / 2, 112, detail, fill="secondary", anchor="middle")

    for y, label, live in ((60, "path 0, udp", True), (100, "path 1, icmp", True), (140, "path 2, udp, unhealthy", False)):
        d.text(400, y - 8, label, fill="secondary" if live else "negative", anchor="middle", mono=True)
        if live:
            d.arrow(272, y, 528, y, stroke="accent", stroke_width=2, both=True)
        else:
            d.arrow(272, y, 528, y, stroke="muted", dash="4 4", both=True)

    d.arrow(656, 96, 704, 96, both=True)
    d.rect(704, top, 96, bottom - top, fill="raised")
    d.name_text(752, 88, "WireGuard", anchor="middle")
    d.name_text(752, 108, "target", anchor="middle")

    d.text(0, 196, "The top row shows WireGuard bytes 1 to 3 on each leg. Amber is a peer token.", fill="secondary")
    return d


def groups():
    d = Diagram(
        "groups", 272, "MUP path groups",
        "One MUP client has two path groups. Peers that send to listen port 51820 use two paths to two servers "
        "that forward to the first WireGuard target. A peer that sends to listen port 51821 uses one path to a "
        "third server that forwards to the second WireGuard target.",
    )
    for y, name in ((60, "peer A"), (108, "peer B"), (182, "peer C")):
        d.text(0, y + 5, name)
        d.arrow(64, y, 112, y, both=True)

    d.rect(112, 32, 152, 200, fill="raised")
    d.line(112, 138, 264, 138)
    for y, port, mode in ((80, "port 51820", "fallback"), (180, "port 51821", "burst")):
        d.name_text(188, y, port, anchor="middle")
        d.text(188, y + 20, mode, fill="secondary", anchor="middle")

    for y, label, server in ((60, "udp", "server 1"), (108, "icmp", "server 2"), (182, "udp", "server 3")):
        d.text(356, y - 8, label, fill="secondary", anchor="middle", mono=True)
        d.arrow(264, y, 448, y, stroke="accent", stroke_width=2, both=True)
        d.rect(448, y - 20, 120, 40, fill="raised")
        d.text(508, y + 5, server, anchor="middle")
        d.arrow(568, y, 648, y, both=True)

    for top, bottom, name in ((40, 128, "target 1"), (162, 202, "target 2")):
        d.rect(648, top, 152, bottom - top, fill="raised")
        d.text(724, (top + bottom) / 2 + 5, f"WireGuard {name}", anchor="middle")

    d.text(0, 260, "The listen port selects the group of a peer. Amber lines carry a peer token.", fill="secondary")
    return d


def modes():
    d = Diagram(
        "modes", 372, "Path modes",
        "Fallback uses the first healthy path. Balancer hashes each peer token to one healthy path. "
        "Burst sends a copy on every healthy path, and the server keeps the first copy.",
    )
    rows = [
        ("Fallback", "--mode fallback", ["Uses the first healthy path,", "in the order of the -u flags."], [
            ("path 0, unhealthy", "down"), ("path 1, in use", "live"), ("path 2, standby", "idle"),
        ]),
        ("Balancer", "--mode balancer", ["Hashes each peer token to one", "healthy path."], [
            ("token 7", "live"), ("token 3", "live"), ("token 12", "live"),
        ]),
        ("Burst", "--mode burst", ["Copies to every healthy path.", "The server keeps the first copy."], [
            ("copy", "live"), ("copy", "live"), ("copy", "live"),
        ]),
    ]
    left, right = 192, 512
    for index, (name, flag, caption, paths) in enumerate(rows):
        top = index * 124
        if index:
            d.line(0, top, WIDTH, top)
        d.name_text(0, top + 36, name)
        d.text(0, top + 56, flag, fill="muted", mono=True)
        d.text(left, top + 16, "client", fill="muted")
        d.text(right, top + 16, "server", fill="muted", anchor="end")
        d.line(left, top + 24, left, top + 112, stroke="text", stroke_width=2)
        d.line(right, top + 24, right, top + 112, stroke="text", stroke_width=2)
        for row, (label, state) in enumerate(paths):
            y = top + 44 + row * 28
            fill = {"live": "secondary", "idle": "muted", "down": "negative"}[state]
            d.text((left + right) / 2, y - 6, label, fill=fill, anchor="middle", mono=True)
            if state == "live":
                d.arrow(left + 1, y, right - 1, y, stroke="accent", stroke_width=2)
            else:
                d.line(left + 1, y, right - 1, y, stroke="muted", dash="4 4")
        for row, line in enumerate(caption):
            d.text(536, top + 56 + row * 20, line, fill="secondary")
    return d


def return_modes():
    d = Diagram(
        "return-modes", 448, "Transports and return modes",
        "UDP direct, UDP reflected with a spoofed source, ICMP direct with Echo Request and Echo Reply, "
        "and ICMP reflected through a reflector host.",
    )
    rows = [
        ("UDP direct", ["-u SERVER:PORT/udp"], "UDP -s:listen → server:port", "UDP server:port → -s:listen"),
        ("UDP reflected", ["-u SERVER:PORT/udp", "-r RETURN_IP"], "UDP -s:listen → server:port", "UDP from -r (spoofed) → -s:listen"),
        ("ICMP direct", ["-u SERVER:PORT/icmp"], "Echo Request, id = port", "Echo Reply, id = port"),
        ("ICMP reflected", ["-u SERVER:PORT/icmp", "-r REFLECTOR_IP"], "Echo Request, id = port", None),
    ]
    left, right = 216, 798
    center = (left + right) / 2
    for index, (name, flags, upstream, downstream) in enumerate(rows):
        top = index * 112
        if index:
            d.line(0, top, WIDTH, top)
        d.name_text(0, top + 32, name)
        for row, flag in enumerate(flags):
            d.text(0, top + 52 + row * 20, flag, fill="muted", mono=True)
        d.text(left, top + 16, "client", fill="muted")
        d.text(right, top + 16, "server", fill="muted", anchor="end")
        d.line(left, top + 24, left, top + 100, stroke="text", stroke_width=2)
        d.line(right, top + 24, right, top + 100, stroke="text", stroke_width=2)
        d.text(center, top + 28, upstream, fill="secondary", anchor="middle", mono=True)
        d.arrow(left + 1, top + 36, right - 1, top + 36)
        if downstream:
            d.arrow(right - 1, top + 64, left + 1, top + 64)
            d.text(center, top + 84, downstream, fill="secondary", anchor="middle", mono=True)
        else:
            d.rect(center - 28, top + 52, 56, 24, fill="raised")
            d.text(center, top + 69, "-r", anchor="middle", mono=True)
            d.arrow(right - 1, top + 64, center + 28, top + 64)
            d.arrow(center - 28, top + 64, left + 1, top + 64)
            d.text((center + right) / 2, top + 92, "Echo Request as -s", fill="secondary", anchor="middle", mono=True)
            d.text((left + center) / 2, top + 92, "Echo Reply", fill="secondary", anchor="middle", mono=True)
    return d


def packet_flow():
    d = Diagram(
        "packet-flow", 576, "Packet flow",
        "A WireGuard packet goes from a peer to the MUP client, over a path to the MUP server, and to the "
        "target. The reply returns on the latest upstream path. Only the legs between client and server carry a peer token.",
    )
    peer, client, server, target = 64, 304, 528, 732
    for x, name in ((peer, "WireGuard peer"), (client, "MUP client"), (server, "MUP server"), (target, "WireGuard target")):
        d.name_text(x, 16, name, anchor="middle")
        d.line(x, 28, x, 568)

    def leg(y, x1, x2, label, value):
        live = value != NO_TOKEN
        d.arrow(x1, y, x2, y, stroke="accent" if live else "secondary", stroke_width=2 if live else 1.5)
        d.text((x1 + x2) / 2, y - 8, label, anchor="middle")
        d.bytes_value((x1 + x2) / 2, y + 22, value)

    def note(x, y, lines):
        for row, line in enumerate(lines):
            d.text(x + 12, y + row * 20, line, fill="secondary")

    leg(64, peer, client, "1  WireGuard over UDP", NO_TOKEN)
    note(client, 112, ["allocate token, pick paths", "write token, rewrite headers"])
    leg(172, client, server, "2  MUP packet on chosen paths", TOKEN)
    note(server, 220, ["match path, drop copies", "take port, clear token"])
    leg(280, server, target, "3  UDP from the target port", NO_TOKEN)
    leg(344, target, server, "4  WireGuard reply", NO_TOKEN)
    note(server, 392, ["find route by port", "write token, pick return"])
    leg(452, server, client, "5  On the latest upstream path", TOKEN)
    note(client, 500, ["check source, look up token", "clear token, rewrite to UDP"])
    leg(536, client, peer, "6  UDP from the listen port", NO_TOKEN)
    return d


def control_plane():
    d = Diagram(
        "control-plane", 288, "Registration and path health",
        "The client sends REGISTER on each path and the server answers REGISTER_ACK. Three missed ACKs make a "
        "path unhealthy, and one ACK makes it healthy. Paths from -u flags start healthy, and paths from mupctl start unhealthy.",
    )
    client, server = 64, 464
    for x, name in ((client, "MUP client"), (server, "MUP server")):
        d.name_text(x, 16, name, anchor="middle")
        d.line(x, 28, x, 280)

    d.text((client + server) / 2, 56, "1  REGISTER", anchor="middle", mono=True)
    d.arrow(client, 64, server, 64)
    d.text((client + server) / 2, 84, "UDP to the port, or an Echo Request", fill="secondary", anchor="middle")
    for row, line in enumerate(["source must equal -s", "a new nonce replaces the old one", "write registration, 30 s lease"]):
        d.text(server - 12, 116 + row * 20, line, fill="secondary", anchor="end")

    d.text((client + server) / 2, 188, "2  REGISTER_ACK, same sequence", anchor="middle", mono=True)
    d.arrow(server, 196, client, 196)
    for row, line in enumerate(["ACK within 900 ms: the path is healthy", "next REGISTER in 10 s, or 1 s after a miss"]):
        d.text(client + 12, 228 + row * 20, line, fill="secondary")

    d.name_text(568, 16, "Path health")
    d.rect(568, 44, 144, 36, fill="raised")
    d.text(640, 67, "healthy", anchor="middle")
    d.rect(568, 164, 144, 36, fill="raised")
    d.text(640, 187, "unhealthy", fill="negative", anchor="middle")
    d.arrow(680, 80, 680, 164)
    d.text(692, 118, "3 missed", fill="secondary")
    d.text(692, 138, "ACKs", fill="secondary")
    d.arrow(600, 164, 600, 80)
    d.text(608, 128, "1 ACK", fill="secondary")
    d.text(568, 236, "-u paths start healthy.", fill="secondary")
    d.text(568, 256, "mupctl paths start unhealthy.", fill="secondary")
    return d


def control_frame():
    d = Diagram(
        "control-frame", 472, "Control frame",
        "The 48-byte control frame in rows of four bytes: magic, version, type, transport, flags, length, status, "
        "path ID, listen port, server port, advertised IP, return IP, instance nonce, sequence, and lease seconds.",
    )
    origin, cell, row_height, top = 56, 186, 36, 28
    fields = [
        (0, 4, "magic", "MUPC"), (4, 1, "version", "1"), (5, 1, "type", ""), (6, 1, "transport", "0 or 1"), (7, 1, "flags", ""),
        (8, 2, "length", "48"), (10, 2, "status", ""), (12, 2, "path ID", "0 to 7"), (14, 2, "listen port", "client -p"),
        (16, 2, "server port", "server -p"), (18, 2, "reserved", "zero"), (20, 4, "advertised IP", "client -s"),
        (24, 4, "return IP", "client -r, or zero"), (28, 8, "instance nonce", "nonzero, random"),
        (36, 4, "sequence", ""), (40, 4, "lease seconds", "30"), (44, 4, "reserved", "zero"),
    ]
    for column in range(4):
        d.text(origin + column * cell + cell / 2, 16, str(column), fill="muted", anchor="middle", mono=True)
    for row in range(12):
        d.text(origin - 16, top + row * row_height + 23, str(row * 4), fill="muted", anchor="end", mono=True)
    for start, length, name, value in fields:
        row, column = divmod(start, 4)
        if length == 8:
            x, y, w, h = origin, top + row * row_height, 4 * cell, 2 * row_height
        else:
            x, y, w, h = origin + column * cell, top + row * row_height, length * cell, row_height
        d.rect(x, y, w, h, radius=0)
        spans = [(name, "muted" if name == "reserved" else "text", False, 400)]
        if value:
            spans.append((f"   {value}", "muted", True, 400))
        d.spans(x + w / 2, y + h / 2 + 5, spans, anchor="middle")
    return d


def lifetimes():
    d = Diagram(
        "lifetimes", 148, "Lifecycle of tokens and ports",
        "A peer token or target port moves from the free queue to a route, then to quarantine, and then back to "
        "the free queue, unless a route owns it again.",
    )
    for x, name, detail in ((0, "free queue", "BPF queue map"), (308, "in use", "two route entries"), (616, "quarantine", "held by Go for 120 s")):
        d.rect(x, 12, 184, 72, fill="raised")
        d.name_text(x + 92, 44, name, anchor="middle")
        d.text(x + 92, 66, detail, fill="secondary", anchor="middle")
    d.arrow(184, 56, 308, 56)
    d.text(246, 46, "first packet", anchor="middle")
    d.arrow(492, 56, 616, 56)
    d.text(554, 28, "idle 180 s,", anchor="middle")
    d.text(554, 46, "or client gone", anchor="middle")
    d.elbow([(708, 84), (708, 112), (92, 112), (92, 84)])
    d.text(400, 136, "Back to the queue, unless a route owns it again", fill="secondary", anchor="middle")
    return d


DIAGRAMS = [packet, overview, groups, modes, return_modes, packet_flow, control_plane, control_frame, lifetimes]


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for build in DIAGRAMS:
        diagram = build()
        for theme in THEMES:
            (OUTPUT / f"{diagram.name}-{theme}.svg").write_text(diagram.render(theme), encoding="utf-8")
    print(f"wrote {len(DIAGRAMS) * len(THEMES)} files to {OUTPUT}")


if __name__ == "__main__":
    main()
