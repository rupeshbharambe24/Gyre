#!/usr/bin/env python3
"""Render the Gyre Shield demo as a looping GIF — no terminal recorder needed.

Draws a faux-terminal "screenplay" of what `scripts/demo.sh` shows (relay up → origin
parks → client admitted → flood refused) with Pillow, then stitches the frames into a
looping GIF with ffmpeg. This is the no-VHS path; `scripts/demo.tape` is the VHS path.

    python3 scripts/make-demo-gif.py            # -> docs/assets/demo.gif

Requires: Pillow, ffmpeg, and a monospace font (JetBrains Mono / Menlo / DejaVu).
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets", "demo.gif")

# Palette (matches the dashboard / deck).
BG = (7, 11, 18)
BAR = (14, 20, 32)
WHITE = (232, 238, 251)
DIM = (107, 122, 153)
CY = (56, 189, 248)
GR = (54, 211, 153)
RD = (255, 92, 114)
AM = (255, 180, 84)

# (text, color, bold). The screenplay, revealed one line per beat.
SCRIPT = [
    ("$ ./scripts/demo.sh", DIM, False),
    ("", WHITE, False),
    ("  ┌──────────────────────────────────────────────┐", CY, True),
    ("  │  GYRE — the inbound Shield, live               │", CY, True),
    ("  │  origin-hiding + a proof-of-work DoS gate      │", CY, True),
    ("  └──────────────────────────────────────────────┘", CY, True),
    ("", WHITE, False),
    ("▸ 1/4  Start the guarded relay (admission gate)", CY, True),
    ("     gyre-rendezvous listening on 127.0.0.1:9500", DIM, False),
    ("     admission gate: SHA-256 PoW per connection", DIM, False),
    ("", WHITE, False),
    ("▸ 2/4  The origin dials OUT and parks", CY, True),
    ("     it binds NO inbound address — nothing to flood", DIM, False),
    ("", WHITE, False),
    ("▸ 3/4  A client solves the puzzle and reaches it", CY, True),
    ("     ✓ ADMITTED  →  reply \"hidden origin: ping\"", GR, True),
    ("", WHITE, False),
    ("▸ 4/4  A flood of 50 connections that SKIP the puzzle", CY, True),
    ("     ✗ 50 refused, 0 served", RD, True),
    ("     gate held · parked map stayed bounded", DIM, False),
    ("", WHITE, False),
    ("✔ pay the work → through;   skip it → refused.", GR, True),
    ("  No volumetric L3/L4 defence (D22) — see docs/DEPLOY.md", DIM, False),
]

W, H = 980, 150 + 30 * len(SCRIPT)
PAD_X, TOP = 26, 58
LH = 30
FS = 20


def find_font(bold):
    pats = (
        ["*JetBrainsMono*NerdFontMono-Bold.ttf", "*JetBrainsMono*-Bold.ttf"]
        if bold
        else ["*JetBrainsMono*NerdFontMono-Regular.ttf", "*JetBrainsMono*-Regular.ttf"]
    )
    for base in [os.path.expanduser("~/Library/Fonts"), "/Library/Fonts"]:
        for pat in pats:
            hits = sorted(glob.glob(os.path.join(base, pat)))
            if hits:
                return ImageFont.truetype(hits[0], FS)
    for p in ["/System/Library/Fonts/Menlo.ttc",
              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]:
        if os.path.exists(p):
            return ImageFont.truetype(p, FS, index=1 if bold and p.endswith(".ttc") else 0)
    return ImageFont.load_default()


def main():
    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found — install it (brew install ffmpeg) and retry.")
    reg, bold = find_font(False), find_font(True)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="gyre-gif-")

    # Reveal schedule: frames to hold after each new line appears (longer on the payoffs).
    hold = [2] * len(SCRIPT)
    for i, (t, _, _) in enumerate(SCRIPT):
        if "ADMITTED" in t or "refused" in t or "pay the work" in t:
            hold[i] = 10
    frame = 0
    for shown in range(1, len(SCRIPT) + 1):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, 38], fill=BAR)
        for i, c in enumerate((RD, AM, GR)):
            d.ellipse([18 + i * 22, 14, 30 + i * 22, 26], fill=c)
        d.text((104, 11), "gyre — live shield demo", font=reg, fill=DIM)
        for row in range(shown):
            text, color, b = SCRIPT[row]
            d.text((PAD_X, TOP + row * LH), text, font=(bold if b else reg), fill=color)
        for _ in range(hold[shown - 1]):
            img.save(os.path.join(tmp, f"f{frame:04d}.png"))
            frame += 1
    for _ in range(24):  # hold the final frame
        img.save(os.path.join(tmp, f"f{frame:04d}.png"))
        frame += 1

    subprocess.run(
        ["ffmpeg", "-y", "-framerate", "12", "-i", os.path.join(tmp, "f%04d.png"),
         "-filter_complex", "[0:v] split [a][b];[a] palettegen=stats_mode=full [p];[b][p] paletteuse",
         "-loop", "0", OUT],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"wrote {OUT} ({os.path.getsize(OUT)//1024} KB, {frame} frames)")


if __name__ == "__main__":
    main()
