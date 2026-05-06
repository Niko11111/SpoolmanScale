import os
import re
import shutil
import json

Import("env")

def copy_release_files(source, target, env):
    build_dir = env.subst("$BUILD_DIR")
    project_dir = env.subst("$PROJECT_DIR")
    src_dir = os.path.join(project_dir, "src")

    # Versionsnummer aus main.cpp lesen
    main_cpp = os.path.join(src_dir, "main.cpp")
    version = "unknown"
    if os.path.exists(main_cpp):
        with open(main_cpp, "r") as f:
            for line in f:
                m = re.search(r'#define FW_VERSION\s+"([^"]+)"', line)
                if m:
                    version = m.group(1)
                    break

    print(f"copy_release: version = {version}")

    # Ordnerstruktur anlegen
    release_base    = os.path.join(project_dir, "releases", version)
    webflasher_dir  = os.path.join(release_base, "webflasher")
    ota_github_dir  = os.path.join(release_base, "ota_github")
    ota_browser_dir = os.path.join(release_base, "ota_browser")
    source_dir      = os.path.join(release_base, "source")
    fonts_dir       = os.path.join(source_dir, "fonts")

    for d in [webflasher_dir, ota_github_dir, ota_browser_dir, source_dir, fonts_dir]:
        os.makedirs(d, exist_ok=True)

    # Webflasher — alle drei Binaries
    for src_name, dst_name in [
        ("bootloader.bin", "bootloader.bin"),
        ("partitions.bin", "partitions.bin"),
        ("firmware.bin",   "SpoolmanScale.bin"),
    ]:
        src = os.path.join(build_dir, src_name)
        dst = os.path.join(webflasher_dir, dst_name)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            print(f"copy_release: -> webflasher/{dst_name}")
        else:
            print(f"copy_release: WARNING {src_name} not found at {src}")

    firmware_bin = os.path.join(build_dir, "firmware.bin")

    # OTA GitHub
    if os.path.exists(firmware_bin):
        shutil.copy2(firmware_bin, os.path.join(ota_github_dir, "SpoolmanScale.bin"))
        print(f"copy_release: -> ota_github/SpoolmanScale.bin")

    # OTA Browser (mit Versionsnummer)
    browser_filename = f"SpoolmanScale_{version}.bin"
    if os.path.exists(firmware_bin):
        shutil.copy2(firmware_bin, os.path.join(ota_browser_dir, browser_filename))
        print(f"copy_release: -> ota_browser/{browser_filename}")

    # Quellcode
    for f in ["main.cpp", "lang.cpp", "lang.h", "lv_conf.h"]:
        src = os.path.join(src_dir, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(source_dir, f))
            print(f"copy_release: -> source/{f}")

    # Build-Scripts + Config
    for f in ["platformio.ini", "copy_release.py", "partitions.csv"]:
        src = os.path.join(project_dir, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(source_dir, f))
            print(f"copy_release: -> source/{f}")

    # Custom Fonts
    lvgl_fonts_src = os.path.join(src_dir, "fonts")
    if os.path.exists(lvgl_fonts_src):
        copied = 0
        for f in os.listdir(lvgl_fonts_src):
            if f.endswith(".c") or f.endswith(".h"):
                shutil.copy2(os.path.join(lvgl_fonts_src, f), os.path.join(fonts_dir, f))
                copied += 1
        print(f"copy_release: -> source/fonts/ ({copied} files)")

    # manifest.json updaten + in Release-Ordner kopieren
    manifest_path = os.path.join(project_dir, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        manifest["version"] = version
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        shutil.copy2(manifest_path, os.path.join(release_base, "manifest.json"))
        print(f"copy_release: manifest.json version -> {version}")

    print(f"copy_release: done -> releases/{version}/")

env.AddPostAction("buildprog", copy_release_files)
