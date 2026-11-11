"""A long message on the main screen's status line ends in "..." on one line
instead of wrapping into the 22 px bar. LVGL dots a LONG_DOT label only where
its text is taller than the label (lv_label_refr_text), so every label of that
bar with LONG_DOT gets one line of height, in its own font, besides its width.
The same for the two other labels of the bar, the address and the diagnosis
banner, which are bounded the same way.

Reads the source without a compiler: comments and strings are blanked and
function bodies found by brace matching, with the tools of the convention
ratchet."""
import re
import sys
from pathlib import Path

root = Path(__file__).parents[1]
src = root / "src"

sys.path.insert(0, str(root / "scripts"))
import check_conventions as cc  # noqa: E402

MAIN = "ui/main_screen.cpp"
BANNER = "ui/diag_banner.cpp"


def squeeze(text):
    """The text without any blank, so that a call is found however it is wrapped."""
    return re.sub(r"\s+", "", text)


def body_of(rel, name):
    """The code between the braces of the one function called name, squeezed."""
    path = src / rel
    assert path.is_file(), f"src/{rel}: file is missing"
    code = cc.Source(path.read_text(encoding="utf-8")).code
    bodies = [code[start + 1:end] for found, start, end in cc.find_functions(code) if found == name]
    assert len(bodies) == 1, f"src/{rel}: {name}() is not defined exactly once"
    return squeeze(bodies[0])


def one_line(body, where, label, font):
    """The label is dotted, has its width and exactly one line of its own font as height."""
    font_set = f"lv_obj_set_style_text_font({label},&{font},0);"
    dotted = f"lv_label_set_long_mode({label},LV_LABEL_LONG_DOT);"
    height = f"lv_obj_set_height({label},lv_font_get_line_height(&{font}));"
    for needle, what in ((font_set, f"its font {font}"), (dotted, "LONG_DOT"),
                         (f"lv_obj_set_width({label},", "a width"), (height, "one line of height in its font")):
        assert body.count(needle) == 1, f"{where}: {label} lacks {what} ({needle})"


def no_other_height(label, keep):
    """Nothing else in src/ gives the label a height or a size: one line stays one line."""
    hits = []
    for path in sorted(src.rglob("*.cpp")):
        code = squeeze(cc.Source(path.read_text(encoding="utf-8")).code)
        for call in ("lv_obj_set_height(", "lv_obj_set_size(", "lv_obj_set_content_height("):
            n = code.count(f"{call}{label},")
            rel = path.relative_to(src).as_posix()
            if rel == keep and call == "lv_obj_set_height(":
                n -= 1
            if n:
                hits.append(f"src/{rel}: {call}{label},...)")
    assert not hits, f"{label} gets another height: {hits}"


def main():
    ui = body_of(MAIN, "buildUI")
    one_line(ui, f"src/{MAIN}: buildUI()", "lbl_status", "lv_font_montserrat_ext_14")
    one_line(ui, f"src/{MAIN}: buildUI()", "lbl_hdr_ip", "lv_font_montserrat_ext_12")
    one_line(body_of(BANNER, "buildBanner"), f"src/{BANNER}: buildBanner()", "banner_lbl",
             "lv_font_montserrat_ext_14")
    no_other_height("lbl_status", MAIN)
    no_other_height("lbl_hdr_ip", MAIN)
    no_other_height("banner_lbl", BANNER)
    print("status line: ok")


main()
