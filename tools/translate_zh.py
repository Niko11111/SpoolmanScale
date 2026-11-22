#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  SpoolmanScale – Localization (i18n)
#  translate_zh.py - Batch translate tools/lang_zh.jsonl via OpenAI-compatible API
#  通过 OpenAI 兼容接口批量翻译 tools/lang_zh.jsonl（支持断点续传与占位符校验）
# ============================================================
"""
Batch translate untranslated entries in tools/lang_zh.jsonl using any
OpenAI-compatible Chat Completions API (resumable, with printf/macro validation).

使用任意 OpenAI 兼容接口批量翻译 tools/lang_zh.jsonl 中尚未翻译的条目
（自动断点续传，写入前硬校验 printf 占位符、LV_SYMBOL 宏及字节缓冲区上限）。

Environment variables / 环境变量示例 (PowerShell):
  $env:OPENAI_BASE_URL = "https://api.deepseek.com/v1"
  $env:OPENAI_API_KEY  = "sk-your-api-key"
  $env:OPENAI_MODEL    = "deepseek-chat"

Usage examples / 用法示例:
  # 1) Test 20 entries first to verify API & translation style:
  #    先试跑 20 条，验证接口连通性与译文风格：
  python tools/translate_zh.py --limit 20

  # 2) Translate all remaining entries (resumable):
  #    全量翻译剩余条目（中断后重跑自动续传）：
  python tools/translate_zh.py

  # 3) Explicit CLI args instead of env vars:
  #    通过命令行参数显式指定接口与模型：
  python tools/translate_zh.py \
      --base-url https://api.deepseek.com/v1 \
      --api-key sk-your-api-key \
      --model deepseek-chat
"""
import argparse
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK_ZH = ROOT / "tools" / "lang_zh.jsonl"
LF = chr(10)

PRINTF_RE = re.compile(r"%(?:%|[+\-#0 ]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|ll|l|z|j|t)?[diuoxXfFeEgGaAcspn])")
MACRO_RE = re.compile(r"\{[A-Za-z_]\w*\}")

SYSTEM_PROMPT = """\
你是嵌入式 3D 打印耗材秤固件 SpoolmanScale（480x320 触摸屏 + 内置 Web 管理页面）的资深中文本地化工程师。
请将输入的 JSON 数组中的每条英文（参考德文）界面文本翻译为自然、专业、简洁的简体中文。

【术语统一表】
- Spoolman / FilaMan / BamBuddy / Spooly / SpoolmanScale / Bambu / Creality / Snapmaker / NIIMBOT / Phomemo：保留英文原名
- AMS / AMS HT / AMS 3H / CFS / NFC / NTAG / MIFARE / WiFi / BLE / OTA / IP / URL / QR / mDNS / UID / UUID / SKU / API / TLS / HTTPS / JSON / SD / I2C / PN532 / PLA / PETG / ABS / TPU：保留英文
- Spool -> 料盘；Empty spool -> 空盘（按钮/短句）或空料盘；Filament -> 耗材
- Tare -> 去皮；Calibrate / Calibration -> 校准；Scale -> 秤 / 称重台；Pad / Pan -> 秤盘
- Link -> 绑定；Unlink -> 解绑；Archive -> 归档；Dried / Drying -> 烘干
- Bay / Slot -> 槽位；Hotend -> 热端；Nozzle -> 喷嘴；Bed -> 热床；Bag -> 包装袋
- Vendor / Maker -> 品牌 / 厂商；Location -> 存放位置 / 位置；Tag -> 标签；Chip -> 芯片

【铁律（必须 100% 遵守，否则固件会崩溃或编译失败）】
1. 严格保留所有 C printf 格式占位符（如 %s、%d、%u、%.0f、%.1f、%02d、%%），类型、数量和出现顺序绝对不能改动！
2. 严格保留所有花括号宏与模板占位符（如 {LV_SYMBOL_OK}、{LV_SYMBOL_WARNING}、{version}、{name} 等），一个字母都不能改，也不要翻译里面的英文。
3. 原文中的字面量 `\\n` 表示换行，请按需原样保留为两个字符 `\\n`（在输出 JSON 字符串里表现为 `\\\\n`），绝对不要输出真实换行符。
4. 原文若包含 HTML 实体（如 &gt;、&times;）或转义引号 `\\\"`，请保留或避免引入未转义的双引号破坏 C 字符串。
5. 屏幕宽度极有限（480x320）：
   - 非 `STR_W_` 开头的均为设备屏幕 UI，务必极度精炼（按钮尽量 2~5 个汉字）。
   - 如果条目提供了 `max_bytes`，译文的 UTF-8 字节数绝对不能超过该值（1 个汉字 = 3 字节）。
   - `STR_W_` 开头为浏览器网页文本，可稍自然流畅，但也保持干练。
   - `STR_WELCOME_TRILINGUAL` 为开机多语欢迎语，请在原多语后追加中文（例如追加 " / 欢迎" 或保持极短）。
6. 只返回一个合法的 JSON 对象，格式为：{"STR_ID_1": "中文译文1", "STR_ID_2": "中文译文2"}，不要包裹 Markdown 代码块，不要输出任何解释文字。
"""


def extract_printf(text):
    # Ignore literal %%
    return [m.group(0) for m in PRINTF_RE.finditer(text) if m.group(0) != "%%"]


def extract_macros(text):
    return sorted(MACRO_RE.findall(text))


def normalize_zh(zh, en):
    zh = zh.strip()
    # Replace accidental real newlines with literal \n
    zh = zh.replace("\r\n", "\\n").replace("\n", "\\n")
    # Escape unescaped double quotes if any
    zh = re.sub(r'(?<!\\)"', r'\"', zh)
    # Collapse accidental full-width percent signs next to format specifiers
    zh = re.sub(r"％(?=[diuoxXfFeEgGaAcspn0-9.%])", "%", zh)
    # Preserve leading/trailing space if original explicitly had one for concatenation
    if en.startswith(" ") and not zh.startswith(" "):
        zh = " " + zh
    if en.endswith(" ") and not zh.endswith(" "):
        zh = zh + " "
    return zh


def validate_entry(rec, zh):
    errs = []
    en = rec.get("en", "")
    if not zh or not zh.strip():
        return ["empty translation"]

    en_fmt = extract_printf(en)
    zh_fmt = extract_printf(zh)
    if en_fmt != zh_fmt:
        errs.append("printf mismatch: en=%s vs zh=%s" % (en_fmt, zh_fmt))

    en_mac = extract_macros(en)
    zh_mac = extract_macros(zh)
    if en_mac != zh_mac:
        errs.append("macro mismatch: en=%s vs zh=%s" % (en_mac, zh_mac))

    max_bytes = rec.get("buf") or rec.get("max_bytes") or rec.get("budget_bytes")
    if isinstance(max_bytes, int) and max_bytes > 0:
        # Unescape \n to 1 byte for real C string byte count estimate
        real_bytes = len(zh.replace("\\n", "\n").replace('\\"', '"').encode("utf-8"))
        if real_bytes >= max_bytes:
            errs.append("exceeds buffer: %d bytes >= %d" % (real_bytes, max_bytes))

    return errs


def call_api(base_url, api_key, model, payload_items, timeout=120):
    url = base_url.rstrip("/") + "/chat/completions"
    user_content = json.dumps(payload_items, ensure_ascii=False, indent=2)
    body = {
        "model": model,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        # Some endpoints reject response_format=json_object; retry once without it
        if e.code == 400 and "response_format" in err_body:
            del body["response_format"]
            req2 = urllib.request.Request(
                url,
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer %s" % api_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                raw = resp2.read().decode("utf-8")
        else:
            raise RuntimeError("HTTP %d: %s" % (e.code, err_body[:500]))

    obj = json.loads(raw)
    content = obj["choices"][0]["message"]["content"].strip()
    # Strip markdown fences if model ignored instruction
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    return json.loads(content)


def load_jsonl(path):
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def save_jsonl_atomic(path, records):
    tmp = path.with_suffix(".jsonl.tmp")
    with open(tmp, "w", encoding="utf-8", newline=LF) as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + LF)
    tmp.replace(path)


def build_payload(batch):
    items = []
    for r in batch:
        item = {"id": r["id"], "en": r.get("en", "")}
        if r.get("de"):
            item["de"] = r["de"]
        max_b = r.get("buf") or r.get("max_bytes") or r.get("budget_bytes")
        if isinstance(max_b, int) and max_b > 0:
            item["max_bytes"] = max_b - 1  # reserve null terminator
        items.append(item)
    return items


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Batch translate tools/lang_zh.jsonl")
    ap.add_argument("--base-url", default=os.environ.get("OPENAI_BASE_URL", "[https://api.deepseek.com/v1](https://api.deepseek.com/v1)"))
    ap.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    ap.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "deepseek-chat"))
    ap.add_argument("--batch-size", type=int, default=40, help="Entries per API call (default: 40)")
    ap.add_argument("--limit", type=int, default=0, help="Max entries to translate this run (0 = all)")
    ap.add_argument("--delay", type=float, default=0.5, help="Seconds to sleep between batches")
    ap.add_argument("--timeout", type=int, default=120, help="HTTP timeout in seconds")
    args = ap.parse_args()

    if not args.api_key:
        print("ERROR: API key missing. Set OPENAI_API_KEY env var or pass --api-key.")
        return 2
    if not WORK_ZH.exists():
        print("ERROR: %s not found. Run: python tools/lang_zh.py seed" % WORK_ZH)
        return 1

    records = load_jsonl(WORK_ZH)
    pending_idx = [i for i, r in enumerate(records) if not (r.get("zh") or "").strip()]
    if args.limit > 0:
        pending_idx = pending_idx[:args.limit]

    total_done = len(records) - len([r for r in records if not (r.get("zh") or "").strip()])
    print("Loaded %d rows (%d already translated, %d queued this run)"
          % (len(records), total_done, len(pending_idx)))
    print("API: %s  model=%s  batch=%d" % (args.base_url, args.model, args.batch_size))

    if not pending_idx:
        print("Nothing to translate.")
        return 0

    accepted = 0
    rejected = []

    for start in range(0, len(pending_idx), args.batch_size):
        chunk_idx = pending_idx[start:start + args.batch_size]
        batch = [records[i] for i in chunk_idx]
        payload = build_payload(batch)
        batch_no = start // args.batch_size + 1
        total_batches = (len(pending_idx) + args.batch_size - 1) // args.batch_size
        print("\n[Batch %d/%d] Translating %d entries (%s .. %s)..."
              % (batch_no, total_batches, len(batch), batch[0]["id"], batch[-1]["id"]))

        result = None
        for attempt in range(1, 4):
            try:
                result = call_api(args.base_url, args.api_key, args.model, payload, args.timeout)
                break
            except Exception as e:
                print("  attempt %d failed: %s" % (attempt, e))
                if attempt < 3:
                    time.sleep(3 * attempt)

        if not isinstance(result, dict):
            print("  SKIPPING batch due to repeated API/JSON errors.")
            continue

        batch_ok = 0
        for idx in chunk_idx:
            rec = records[idx]
            sid = rec["id"]
            if sid not in result or not isinstance(result[sid], str):
                rejected.append((sid, "missing from model output"))
                continue
            zh = normalize_zh(result[sid], rec.get("en", ""))
            errs = validate_entry(rec, zh)
            if errs:
                rejected.append((sid, "; ".join(errs) + " | got=" + repr(zh)))
                continue
            rec["zh"] = zh
            batch_ok += 1
            accepted += 1

        save_jsonl_atomic(WORK_ZH, records)
        print("  saved: +%d ok (cumulative +%d / %d)" % (batch_ok, accepted, len(pending_idx)))
        if args.delay > 0 and start + args.batch_size < len(pending_idx):
            time.sleep(args.delay)

    print("\n=== Done ===")
    print("Accepted: %d" % accepted)
    if rejected:
        print("Rejected (%d) - left empty in lang_zh.jsonl for retry/manual fix:" % len(rejected))
        for sid, reason in rejected[:30]:
            print("  %-32s %s" % (sid, reason))
        if len(rejected) > 30:
            print("  ... and %d more" % (len(rejected) - 30))
    return 0


if __name__ == "__main__":
    sys.exit(main())