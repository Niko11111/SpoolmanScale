import os
import re
import shutil
import json

Import("env")

def copy_release_files(source, target, env):
    build_dir = env.subst("$BUILD_DIR")
    project_dir = env.subst("$PROJECT_DIR")
    src_dir = os.path.join(project_dir, "src")

    # Versionsnummer aus main.cpp/app_config.h lesen
    version = "unknown"
    for version_file in ["app_config.h", "main.cpp"]:
        path = os.path.join(src_dir, version_file)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r'#define FW_VERSION\s+"([^"]+)"', line)
                if m:
                    version = m.group(1)
                    break
        if version != "unknown":
            break

    print(f"copy_release: version = {version}")

    is_hx711 = env.subst("$PIOENV") == "wt32-sc01-plus-hx711"

    # Ordnerstruktur anlegen
    release_base    = os.path.join(project_dir, "releases", version)
    webflasher_dir  = os.path.join(release_base, "webflasher")
    if is_hx711:
        webflasher_dir = os.path.join(webflasher_dir, "hx711")
    ota_github_dir  = os.path.join(release_base, "ota_github")
    ota_browser_dir = os.path.join(release_base, "ota_browser")
    source_dir      = os.path.join(release_base, "source")

    for d in [webflasher_dir, ota_github_dir, ota_browser_dir, source_dir]:
        os.makedirs(d, exist_ok=True)

    # Webflasher binaries for the selected ADC profile. Keep the HX711 payload
    # in its own subdirectory so a local build cannot replace the NAU7802 image.
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

    # The web manifest also references the boot_app0 metadata image. It is
    # supplied by a previously populated webflasher directory when available.
    app0_candidates = [
        os.path.join(project_dir, "webflasher", "hx711" if is_hx711 else "", "boot_app0.bin"),
        os.path.join(project_dir, "webflasher", "boot_app0.bin"),
    ]
    for app0_src in app0_candidates:
        if os.path.exists(app0_src):
            shutil.copy2(app0_src, os.path.join(webflasher_dir, "boot_app0.bin"))
            break

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
    if os.path.exists(src_dir):
        for name in os.listdir(source_dir):
            path = os.path.join(source_dir, name)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        shutil.copytree(src_dir, source_dir, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
        print("copy_release: -> source/")

    # Build-Scripts + Config
    for f in ["platformio.ini", "copy_release.py", "partitions.csv"]:
        src = os.path.join(project_dir, f)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(source_dir, f))
            print(f"copy_release: -> source/{f}")

    # manifest.json updaten + in Release-Ordner kopieren
    manifest_name = "manifest-hx711.json" if is_hx711 else "manifest.json"
    manifest_path = os.path.join(project_dir, manifest_name)
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        manifest["version"] = version
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        shutil.copy2(manifest_path, os.path.join(release_base, manifest_name))
        print(f"copy_release: {manifest_name} version -> {version}")

    print(f"copy_release: done -> releases/{version}/")

env.AddPostAction("buildprog", copy_release_files)
