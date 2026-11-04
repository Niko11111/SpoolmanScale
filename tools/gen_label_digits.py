#!/usr/bin/env python3
"""Write src/services/label_digits_data.h: the digits 0-9 of a TrueType font as flat outlines.

A spool's number on a label is drawn from these outlines at whatever height it
fits (services/label_digits.h), so it needs no bitmap font per size. No
dependency beyond Python: the few tables this needs are read directly.

Usage: tools/gen_label_digits.py [font.ttf]
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
DEFAULT_FONT = ROOT / ".pio/libdeps/wt32-sc01-plus/lvgl/scripts/built_in_font/Montserrat-Medium.ttf"
OUTPUT = ROOT / "src/services/label_digits_data.h"
# How far a flattened curve may stray from the real one, in font units of a
# 1000 unit em. The largest number on any label is some 330 dots for 730 units,
# so this stays under a dot.
FLATNESS_UNITS = 1.5
ON_CURVE, X_SHORT, Y_SHORT, REPEAT, X_SAME, Y_SAME = 1, 2, 4, 8, 16, 32


def tables(data):
    count = struct.unpack(">H", data[4:6])[0]
    found = {}
    for i in range(count):
        tag, _, offset, length = struct.unpack(">4sIII", data[12 + i * 16:28 + i * 16])
        found[tag.decode()] = data[offset:offset + length]
    return found


def glyph_for(cmap, char):
    """The glyph of a character from the Unicode format 4 subtable."""
    for i in range(struct.unpack(">H", cmap[2:4])[0]):
        offset = struct.unpack(">I", cmap[8 + i * 8:12 + i * 8])[0]
        sub = cmap[offset:]
        if struct.unpack(">H", sub[:2])[0] != 4:
            continue
        segs = struct.unpack(">H", sub[6:8])[0] // 2
        ends = struct.unpack(f">{segs}H", sub[14:14 + segs * 2])
        starts = struct.unpack(f">{segs}H", sub[16 + segs * 2:16 + segs * 4])
        deltas = struct.unpack(f">{segs}h", sub[16 + segs * 4:16 + segs * 6])
        ranges = struct.unpack(f">{segs}H", sub[16 + segs * 6:16 + segs * 8])
        for s in range(segs):
            if not starts[s] <= char <= ends[s]:
                continue
            if ranges[s] == 0:
                return (char + deltas[s]) & 0xFFFF
            at = 16 + segs * 6 + s * 2 + ranges[s] + (char - starts[s]) * 2
            return (struct.unpack(">H", sub[at:at + 2])[0] + deltas[s]) & 0xFFFF
    raise SystemExit(f"no glyph for U+{char:04X}")


def read_deltas(raw, at, flags, short_bit, same_bit):
    values, value = [], 0
    for flag in flags:
        if flag & short_bit:
            value += raw[at] if flag & same_bit else -raw[at]
            at += 1
        elif not flag & same_bit:
            value += struct.unpack(">h", raw[at:at + 2])[0]
            at += 2
        values.append(value)
    return values, at


def contours_of(raw):
    """A simple glyph's contours, each a list of (x, y, on_curve)."""
    contour_count = struct.unpack(">h", raw[:2])[0]
    if contour_count <= 0:
        raise SystemExit("a digit is a composite glyph, which this reader does not take")
    ends = struct.unpack(f">{contour_count}H", raw[10:10 + contour_count * 2])
    at = 10 + contour_count * 2
    at += 2 + struct.unpack(">H", raw[at:at + 2])[0]
    flags = []
    while len(flags) <= ends[-1]:
        flag = raw[at]
        at += 1
        flags.append(flag)
        if flag & REPEAT:
            flags.extend([flag] * raw[at])
            at += 1
    xs, at = read_deltas(raw, at, flags, X_SHORT, X_SAME)
    ys, at = read_deltas(raw, at, flags, Y_SHORT, Y_SAME)
    contours, first = [], 0
    for end in ends:
        contours.append([(xs[i], ys[i], bool(flags[i] & ON_CURVE)) for i in range(first, end + 1)])
        first = end + 1
    return contours


def flatten(contour):
    """A TrueType contour as straight segments: quadratic curves, implied on-curve points."""
    points = []
    for i, p in enumerate(contour):
        q = contour[(i + 1) % len(contour)]
        points.append(p)
        if not p[2] and not q[2]:
            points.append(((p[0] + q[0]) / 2, (p[1] + q[1]) / 2, True))
    start = next(i for i, p in enumerate(points) if p[2])
    points = points[start:] + points[:start]
    out, i = [], 0
    while i < len(points):
        a = points[i]
        out.append((a[0], a[1]))
        nxt = points[(i + 1) % len(points)]
        if nxt[2]:
            i += 1
            continue
        b = points[(i + 2) % len(points)]
        # The deviation of a quadratic falls with the square of the steps.
        bend = (abs(a[0] - 2 * nxt[0] + b[0]) + abs(a[1] - 2 * nxt[1] + b[1])) / 4
        steps = max(1, int((bend / FLATNESS_UNITS) ** 0.5 + 0.999))
        for s in range(1, steps):
            t = s / steps
            u = 1 - t
            out.append((u * u * a[0] + 2 * u * t * nxt[0] + t * t * b[0],
                        u * u * a[1] + 2 * u * t * nxt[1] + t * t * b[1]))
        i += 2
    return [(round(x), round(y)) for x, y in out]


def main():
    font = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_FONT
    t = tables(font.read_bytes())
    long_loca = struct.unpack(">h", t["head"][50:52])[0] == 1
    metrics = struct.unpack(">H", t["hhea"][34:36])[0]

    def glyph_bytes(gid):
        if long_loca:
            a, b = struct.unpack(">II", t["loca"][gid * 4:gid * 4 + 8])
        else:
            a, b = (v * 2 for v in struct.unpack(">HH", t["loca"][gid * 2:gid * 2 + 4]))
        return t["glyf"][a:b]

    points, ends, glyphs = [], [], []
    for digit in "0123456789":
        gid = glyph_for(t["cmap"], ord(digit))
        advance = struct.unpack(">H", t["hmtx"][min(gid, metrics - 1) * 4:min(gid, metrics - 1) * 4 + 2])[0]
        first_point, first_end = len(points), len(ends)
        for contour in contours_of(glyph_bytes(gid)):
            points.extend(flatten(contour))
            ends.append(len(points))
        xs = [p[0] for p in points[first_point:]]
        glyphs.append((advance, min(xs), max(xs), first_point, first_end, len(ends) - first_end))
    ys = [p[1] for p in points]

    lines = [
        "#pragma once",
        "",
        "// Generated by tools/gen_label_digits.py from Montserrat Medium. Do not edit.",
        "// The digits 0-9 as closed polygons, in font units with y up.",
        "",
        "#include <stdint.h>",
        "",
        f"#define LD_Y_MIN {min(ys)}",
        f"#define LD_Y_MAX {max(ys)}",
        "",
        "struct LabelDigitGlyph {",
        "  int16_t advance, x_min, x_max;",
        "  uint16_t first_point, first_contour, contours;",
        "};",
        "",
        "static const LabelDigitGlyph LD_GLYPHS[10] = {",
    ]
    lines += ["  { " + ", ".join(str(v) for v in g) + " }," for g in glyphs]
    lines += ["};", "", "// One past each contour's last point.", "static const uint16_t LD_CONTOUR_ENDS[] = {"]
    lines += ["  " + ", ".join(str(e) for e in ends) + ",", "};", "", "static const int16_t LD_POINTS[][2] = {"]
    for i in range(0, len(points), 8):
        lines.append("  " + " ".join(f"{{{x},{y}}}," for x, y in points[i:i + 8]))
    lines += ["};", ""]
    OUTPUT.write_text("\n".join(lines))
    print(f"{len(points)} points, {len(ends)} contours, {len(points) * 4 + len(ends) * 2 + 120} bytes of flash")


if __name__ == "__main__":
    main()
