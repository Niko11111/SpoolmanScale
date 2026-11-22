// ============================================================
//  SpoolmanScale – Localization (i18n)
//  lang.cpp - String table DE / EN / FR / ZH
// ============================================================
#include <lvgl.h>
#include "services/tag_write.h"   // the TagWriteResult codes
#include "lang.h"

Lang   g_lang     = LANG_EN;
uint8_t g_date_fmt = DATE_FMT_DMY;

// Order MUST exactly match the StringID enum in lang.h!
// Format: { "Deutsch", "English", "Francais", "Chinese" }
const char* const STRINGS[][4] = {

  // Navigation
  { "Abbrechen",       "Cancel",       "Annuler",        "取消" },  // STR_CANCEL
  { "Zurück",          "Back",         "Retour",         "返回" },  // STR_BACK
  { "Bestätigen",      "Confirm",      "Confirmer",      "确认" },  // STR_CONFIRM
  { "ID neu eingeben", "Enter new ID", "Ressaisir l'ID", "输入新 ID" },  // STR_ENTER_NEW_ID

  // Mainscreen Labels
  { "Spoolman",         "Spoolman",    "Spoolman",        "Spoolman" },  // STR_LBL_SPOOLMAN
  { "Waage",            "Scale",       "Balance",         "称重台" },  // STR_LBL_SCALE
  { "Letzte Benutzung", "Last used",   "Dernier usage",   "上次使用" },  // STR_LBL_LAST_USED
  { "Letzte Trocknung", "Last dried",  "Dernier séchage", "上次烘干" },  // STR_LBL_LAST_DRIED
  { "Temperatur",       "Temperature", "Température",     "温度" },  // STR_LBL_TEMP
  { "Hersteller",       "Vendor",      "Fabricant",       "品牌" },  // STR_LBL_VENDOR

  // Mainscreen Status
  { "Spule an Reader halten...", "Hold spool near reader...", "Présentez la bobine...",
    "请将料盘靠近读卡器..." },  // STR_WAIT_SCAN
  { "NFC Tag erkannt", "NFC tag detected", "Tag NFC détecté",
    "检测到 NFC 标签" },  // STR_TAG_FOUND
  { "Kein WLAN",                 "No WiFi",                   "Pas de WiFi",            "无 WiFi" },  // STR_NO_WIFI
  { "Warte...",                  "Please wait...",            "Patientez...",           "请稍候..." },  // STR_WAIT
  { "Warte auf Scan...", "Waiting for scan...", "Attente du scan...",
    "等待扫描..." },  // STR_WAIT_SCAN_SM
  { "unbekannt",                 "unknown",                   "inconnu",                "未知" },  // STR_UNKNOWN
  { "nicht lesbar",              "not readable",              "illisible",              "无法读取" },  // STR_NOT_READABLE
  { "heute",                     "today",                     "aujourd'hui",            "今天" },  // STR_TODAY
  { "gestern",                   "yesterday",                 "hier",                   "昨天" },  // STR_YESTERDAY
  { "vor %d Tagen",              "%d days ago",               "il y a %d jours",        "%d 天前" },  // STR_DAYS_AGO
  { "Fehler beim Speichern",     "Error saving",              "Échec de sauvegarde",    "保存失败" },  // STR_ERR_SAVE
  { "Nicht in Spoolman", "Not in Spoolman", "Hors Spoolman",
    "不在 Spoolman 中" },  // STR_NOT_IN_SPOOLMAN
  { "Archiviert",                "Archived",                  "Archivée",               "已归档" },  // STR_ARCHIVED
  { "Lese Tag...", "Reading tag...", "Lecture du tag...",
    "正在读取标签..." },  // STR_READING_TAG
  { "Durchsuche Inventar...", "Searching inventory...",
    "Parcours de l'inventaire...",
    "正在搜索库存..." },  // STR_SEARCHING_INVENTORY
  { "Durchsuche Inventar... %u KB", "Searching inventory... %u KB",
    "Parcours de l'inventaire... %u ko",
    "正在搜索库存... %u KB" },  // STR_SEARCHING_INVENTORY_KB

  // Mainscreen Buttons
  { "Gewicht updaten",  "Update Weight", "Envoyer le poids", "更新重量" },  // STR_BTN_WEIGHT
  { "Heute getrocknet", "Dried today",   "Noter le séchage", "今日已烘干" },  // STR_BTN_DRIED
  { "Spule verknüpfen", "Link Spool",    "Lier la bobine",   "绑定料盘" },  // STR_BTN_LINK

  // Welcome Screen

  // WiFi Setup
  { "WLAN einrichten",          "WiFi setup",           "Réglage du WiFi",          "WiFi 设置" },  // STR_WIFI_TITLE
  { "Netzwerke suchen...",      "Scanning networks...", "Recherche des réseaux...", "正在扫描网络..." },  // STR_WIFI_SCAN
  { "Keine Netzwerke gefunden", "No networks found",    "Aucun réseau trouvé",      "未找到网络" },  // STR_WIFI_NO_NET
  { "Passwort für: %s",         "Password for: %s",     "Pour le réseau %s",        "%s 的密码" },  // STR_WIFI_PASS_HINT
  { "Passwort...", "Password...", "Mot de passe...",
    "密码..." },  // STR_WIFI_PASS_PLACEHOLDER
  { "Verbinde mit %s...", "Connecting to %s...", "Connexion à %s...",
    "正在连接 %s..." },  // STR_WIFI_CONNECTING

  // Spoolman IP
  { "Spoolman Server", "Spoolman Server", "Serveur Spoolman", "Spoolman 服务器" },  // STR_SPOOLMAN_TITLE

  // Settings
  { "Einstellungen", "Settings",   "Réglages",  "设置" },  // STR_SETTINGS_TITLE
  { "Verbindung",    "Connection", "Connexion", "连接" },  // STR_TILE_CONNECTION
  { "WLAN | Bluetooth | Spoolman", "WiFi | Bluetooth | Spoolman",
    "WiFi | Bluetooth | Spoolman",
    "WiFi | 蓝牙 | Spoolman" },  // STR_TILE_CONN_SUB
  { "Spulen & Waage", "Spools & scale", "Bobines et balance", "料盘与秤" },  // STR_TILE_SCALE
  { "Tags | Trocknung | Kalibrieren", "Tags | Drying | Calibration",
    "Tags | Séchage | Étalonnage",
    "标签 | 烘干 | 校准" },  // STR_TILE_SCALE_SUB
  { "Display", "Display", "Affichage", "显示" },  // STR_TILE_DISPLAY
  { "Helligkeit | Dimmen | Schlaf", "Brightness | Dim | Sleep",
    "Luminosité | Atténuer | Veille",
    "亮度 | 变暗 | 休眠" },  // STR_TILE_DISPLAY_SUB
  { "System", "System", "Système", "系统" },  // STR_TILE_SYSTEM
  { "Web | Update | Sprache | Info", "Web | Update | Language | Info",
    "Web | Mise à jour | Langue | Info",
    "网页 | 更新 | 语言 | 信息" },  // STR_TILE_SYSTEM_SUB

  // Connection
  { "WLAN-Einstellungen", "WiFi settings",     "Réglages WiFi",          "WiFi 设置" },  // STR_BTN_WIFI_SETTINGS
  { "Nicht konfiguriert", "Not configured",    "Non configuré",          "未配置" },  // STR_BTN_WIFI_NONE
  { "WLAN-Status",        "WiFi status",       "État du WiFi",           "WiFi 状态" },  // STR_BTN_WIFI_STATUS
  { "Nicht verbunden",    "Not connected",     "Sans connexion",         "未连接" },  // STR_BTN_WIFI_STATUS_SUB
  { "Server, OTA, Logs",  "Server, OTA, logs", "Serveur, OTA, journaux", "服务器/OTA/日志" },  // STR_BTN_WEB_SUB
  { "Webserver",          "Web server",        "Serveur web",            "Web 服务器" },  // STR_WEB_SERVER
  { "Wartung",            "Maintenance",       "Maintenance",            "维护" },  // STR_WEB_MAINT
  { "Einstellungen",      "Settings",          "Réglages",               "设置" },  // STR_WEB_CONFIG
  { "Aus: Port 80 antwortet nicht.",
    "Off: nothing answers on port 80.",
    "Désactivé : inaccessible depuis le navigateur.",
    "关闭：80 端口无响应。" },  // STR_WEB_SERVER_HINT
  { "Schaltet die Weboberfläche im Netz an und aus. Ausgeschaltet antwortet Port 80 nicht mehr - außer FilaMan hat ein Geräte-Token hinterlegt, dann bleibt allein dessen Tag-Auslöser erreichbar.",
    "Turns the web interface on and off across the network. Switched off, port 80 stops answering - unless FilaMan holds a device token, in which case only its tag trigger stays reachable.",
    "Active ou désactive l'interface web sur le réseau. Désactivée, elle ne répond plus (port 80) - sauf avec FilaMan, si la balance y est associée : seules les lectures et écritures de tag demandées par FilaMan restent alors possibles.",
    "开启或关闭局域网 Web 界面。关闭后 80 端口不再响应；若 FilaMan 存有设备令牌，则仅保留其标签触发接口可访问。" },  // STR_WEB_SERVER_INFO
  { "Liefert Firmware-Upload, Logs, Neustart und das Tag-Schreiben. Standardmäßig aus: schreibt Firmware und NFC-Tags, ohne Passwort.",
    "Serves firmware upload, logs, restart and tag writing. Off by default: these write firmware and NFC tags, with no password.",
    "Rend accessibles dans le navigateur l'envoi de firmware, les journaux, le redémarrage et l'écriture de tags. Désactivé par défaut : sans mot de passe, tout appareil du réseau pourrait installer un firmware et écrire des tags NFC.",
    "提供固件上传、日志、重启及标签写入功能。默认关闭：写入固件和 NFC 标签无需密码。" },  // STR_WEB_MAINT_HINT
  { "Firmware, Logs, Tags, Neustart",
    "Firmware, logs, tags, restart",
    "Firmware, journaux, tags, redémarrage",
    "固件、日志、标签、重启" },  // STR_WEB_MAINT_SUB
  { "Liefert Listenlimits, Trocknung, Anzeige und die Backend-Zugangsdaten. Standardmäßig aus: ändert Einstellungen ohne Passwort.",
    "Serves list limits, drying, display and the backend credentials. Off by default: changes settings with no password.",
    "Rend accessibles dans le navigateur les limites de liste, le séchage, l'affichage et les identifiants du backend. Désactivé par défaut : sans mot de passe, tout appareil du réseau pourrait modifier les réglages.",
    "提供列表上限、烘干、显示及后端凭据设置。默认关闭：修改设置无需密码。" },  // STR_WEB_CONFIG_HINT
  { "Listenlimits, Trocknung, Anzeige",
    "List limits, drying, display",
    "Limites de liste, séchage, affichage",
    "列表上限、烘干、显示" },  // STR_WEB_CONFIG_SUB

  // Scale
  { "Spulen & Waage", "Spools & scale", "Bobines et balance", "料盘与秤" },  // STR_SCALE_TITLE
  { "Kalibrierung",   "Calibration",    "Étalonnage",         "校准" },  // STR_BTN_CALIBRATE
  { "Beutelgewicht",  "Bag weight",     "Poids du sachet",    "包装袋重" },  // STR_BTN_BAGWEIGHT

  // Calibration
  { "Kalibrierung",             "Calibration",              "Étalonnage",              "校准" },  // STR_CAL_TITLE
  { "Fehler: Gewicht = 0", "Error: weight = 0", "Erreur : poids = 0",
    "错误：重量 = 0" },  // STR_CAL_ZERO_ERR
  { LV_SYMBOL_OK "  Berechnen", LV_SYMBOL_OK "  Calculate", LV_SYMBOL_OK "  Calculer",
    LV_SYMBOL_OK "  计算" },  // STR_BTN_CALCULATE

  // Bag weight
  { "Vakuumbeutel inkl. Silikagelpack in Gramm, 0 = kein Beutel",
    "Vacuum bag incl. silica gel pack in grams, 0 = no bag",
    "Sachet sous vide, gel de silice en g, 0 = sans sachet",
    "真空袋含干燥剂总重（克），0 = 无包装袋" },  // STR_BAG_DESC
  { "%.1fg gespeichert", "%.1fg saved",   "%.1fg enregistré", "已保存 %.1fg" },  // STR_BAG_SAVED
  { "Ungültiger Wert",   "Invalid value", "Valeur invalide",  "数值无效" },  // STR_BAG_INVALID

  // Display
  { "Display", "Display", "Affichage", "显示" },  // STR_DISPLAY_TITLE
  { LV_SYMBOL_IMAGE "  Helligkeit",
    LV_SYMBOL_IMAGE "  Brightness",
    LV_SYMBOL_IMAGE "  Luminosité",
    LV_SYMBOL_IMAGE "  屏幕亮度" },  // STR_BRIGHT_LABEL
  { LV_SYMBOL_EYE_OPEN "  Dimmen nach (Min.)",
    LV_SYMBOL_EYE_OPEN "  Dim after (min.)",
    LV_SYMBOL_EYE_OPEN "  Atténuer après (min)",
    LV_SYMBOL_EYE_OPEN "  息屏调暗（分钟）" },  // STR_DIM_LABEL
  { LV_SYMBOL_POWER "  Tiefschlaf nach (Min.)",
    LV_SYMBOL_POWER "  Deep sleep after (min.)",
    LV_SYMBOL_POWER "  Veille profonde après (min)",
    LV_SYMBOL_POWER "  深度休眠（分钟）" },  // STR_SLEEP_LABEL

  // System
  { "System", "System",
    "Système",
    "系统" },  // STR_SYSTEM_TITLE
  { "Deutsch / English / Français", "Deutsch / English / Français",
    "Deutsch / English / Français",
    "中文 / EN / DE / FR" },  // STR_BTN_LANG_SUB
  { "Firmware Update", "Firmware Update",
    "Mise à jour firmware",
    "固件更新" },  // STR_BTN_FW_UPDATE
  { "Browser oder GitHub", "Browser or GitHub",
    "Navigateur ou GitHub",
    "浏览器或 GitHub" },  // STR_BTN_FW_SUB
  { "Info & Unterstützung", "Info & Support",
    "Info et soutien",
    "信息与支持" },  // STR_BTN_INFO
  { "Anleitung - Ko-fi - GitHub - Discord - MakerWorld", "Manual - Ko-fi - GitHub - Discord - MakerWorld",
    "Manuel - Ko-fi - GitHub - Discord - MakerWorld",
    "手册 - Ko-fi - GitHub - Discord - MakerWorld" },  // STR_BTN_INFO_SUB

  // Language screen
  { "Sprache / Language", "Sprache / Language", "Langue / Language", "语言 / Language" },  // STR_LANG_TITLE
  { "Gerät startet nach Auswahl neu.",
    "Device will reboot after selection.",
    "Choisir une langue ou un format de date redémarre l'appareil.",
    "选择后设备将自动重启。" },  // STR_LANG_HINT
  { "Datum / Date format:", "Datum / Date format:", "Format de date :", "日期格式：" },  // STR_DATE_FMT_LABEL

  // OTA
  { "Firmware Update", "Firmware Update",
    "Mise à jour firmware",
    "固件更新" },  // STR_OTA_TITLE
  { "Upload via Webbrowser", "Upload via web browser",
    "Envoi par navigateur web",
    "通过网页上传" },  // STR_OTA_BROWSER
  { ".bin vom PC + SD-Logging", "Upload from PC + SD logging",
    "Depuis le PC + journal SD",
    "PC 端上传 + SD 日志" },  // STR_OTA_BROWSER_SUB
  { "Update via GitHub", "Update via GitHub",
    "Mise à jour par GitHub",
    "通过 GitHub 更新" },  // STR_OTA_GITHUB
  { "Direkt-Update aus GitHub Releases", "Direct update from GitHub Releases",
    "Mise à jour directe depuis GitHub Releases",
    "直接从 GitHub Releases 更新" },  // STR_OTA_GITHUB_SUB
  { "Browser Update", "Browser Update",
    "Mise à jour par navigateur",
    "网页更新" },  // STR_OTA_BROWSER_TITLE
  { LV_SYMBOL_WARNING "  Kein WiFi\nBitte zuerst WiFi einrichten.",
    LV_SYMBOL_WARNING "  No WiFi\nPlease set up WiFi first.",
    LV_SYMBOL_WARNING "  Pas de WiFi\nConfigurez d'abord le WiFi.",
    LV_SYMBOL_WARNING "  无 WiFi\n请先配置 WiFi。" },  // STR_OTA_NO_WIFI
  { "Browser öffnen und aufrufen:",
    "Open browser and go to:",
    "Ouvrez un navigateur et allez à :",
    "打开浏览器并访问：" },  // STR_OTA_OPEN_BROWSER
  { LV_SYMBOL_WIFI "  Warte auf Upload...",
    LV_SYMBOL_WIFI "  Waiting for upload...",
    LV_SYMBOL_WIFI "  Attente de l'envoi...",
    LV_SYMBOL_WIFI "  等待上传..." },  // STR_OTA_WAITING
  { LV_SYMBOL_DOWNLOAD "  Lade hoch...",
    LV_SYMBOL_DOWNLOAD "  Uploading...",
    LV_SYMBOL_DOWNLOAD "  Envoi en cours...",
    LV_SYMBOL_DOWNLOAD "  正在上传..." },  // STR_OTA_UPLOADING
  { LV_SYMBOL_OK "  Update OK! Starte neu...",
    LV_SYMBOL_OK "  Update OK! Restarting...",
    LV_SYMBOL_OK "  Mise à jour OK ! Redémarrage...",
    LV_SYMBOL_OK "  更新成功！正在重启..." },  // STR_OTA_SUCCESS
  { LV_SYMBOL_WARNING "  Update fehlgeschlagen",
    LV_SYMBOL_WARNING "  Update failed",
    LV_SYMBOL_WARNING "  Échec de la mise à jour",
    LV_SYMBOL_WARNING "  更新失败" },  // STR_OTA_FAIL
  { "Aktuell: %s", "Current: %s", "Actuelle : %s", "当前: %s" },  // STR_OTA_CURRENT

  // QR Popups
  { "Projekt gefällt dir? Kauf mir einen Kaffee!",
    "Support this project!",
    "Le projet vous plaît ? Offrez-moi un café !",
    "赞助支持本项目！" },  // STR_QR_KOFI_DESC
  { "Quellcode, Releases & Dokumentation",
    "Source code, releases & docs",
    "Code source, versions et documentation",
    "源码、固件发布与文档" },  // STR_QR_GITHUB_DESC
  { "Community, Fragen & Support",
    "Community, questions & support",
    "Communauté, questions et entraide",
    "社区交流、提问与支持" },  // STR_QR_DISCORD_DESC
  { "3D-Modelle & Designs auf MakerWorld",
    "3D models & designs on MakerWorld",
    "Modèles 3D et créations sur MakerWorld",
    "MakerWorld 上的 3D 模型与设计" },  // STR_QR_MAKER_DESC

  // Weight popup
  { "Heute getrocknet\nspeichern?", "Save dried\ntoday?",
    "Enregistrer le séchage\nd'aujourd'hui ?",
    "记录今日\n已烘干？" },  // STR_POPUP_DRIED_Q
  { "Ja, bestätigen", "Yes, confirm", "Oui, confirmer", "确认" },  // STR_BTN_CONFIRMED


  // Link Flow
  { "Bambu-Spule verknüpfen", "Link Bambu spool",  "Lier une bobine Bambu", "绑定 Bambu 料盘" },  // STR_LINK_BAMBU_TITLE
  { "Unbekannte Spule",       "Unknown spool",     "Bobine inconnue",       "未知料盘" },  // STR_LINK_NTAG_TITLE
  { "Spool-ID eingeben",      "Enter Spool-ID",    "Saisir l'ID de bobine", "输入料盘 ID" },  // STR_BTN_ENTER_ID
  { "Aus Liste wählen",       "Choose from list",  "Choisir dans la liste", "从列表选择" },  // STR_BTN_FROM_LIST
  { "Spoolman Spool-ID",      "Spoolman Spool-ID", "ID de bobine Spoolman", "Spoolman 料盘 ID" },  // STR_LINK_ID_TITLE
  { "Prüfe...",               "Checking...",       "Vérification...",       "查询中..." },  // STR_LINK_CHECKING
  { "ID nicht gefunden",      "ID not found",      "ID introuvable",        "未找到该 ID" },  // STR_LINK_ID_NOT_FOUND
  { "HTTP Fehler %d",         "HTTP Error %d",     "Erreur HTTP %d",        "HTTP 错误 %d" },  // STR_LINK_HTTP_ERR
  { "JSON Fehler",            "JSON error",        "Erreur JSON",           "JSON 错误" },  // STR_LINK_JSON_ERR
  { "Kein WLAN",              "No WiFi",           "Pas de WiFi",           "无 WiFi" },  // STR_LINK_NO_WIFI
  { LV_SYMBOL_WARNING "  Spule bereits verknüpft",
    LV_SYMBOL_WARNING "  Tag already assigned!",
    LV_SYMBOL_WARNING "  Bobine déjà liée",
    LV_SYMBOL_WARNING "  标签已绑定！" },  // STR_WARN_A_TITLE
  { LV_SYMBOL_WARNING "  Trotzdem verknüpfen",
    LV_SYMBOL_WARNING "  Link anyway",
    LV_SYMBOL_WARNING "  Lier quand même",
    LV_SYMBOL_WARNING "  强制绑定" },  // STR_BTN_OVERWRITE
  { "Material stimmt nicht überein", "Material mismatch", "Le matériau ne correspond pas",
    "材质不匹配" },  // STR_WARN_B_TITLE
  { "Tag:      %s\nSpoolman: %s  (#%d)\n\nFalsche ID? Bitte nochmal prüfen.",
    "Tag:      %s\nSpoolman: %s  (#%d)\n\nWrong ID? Please double-check.",
    "Tag :      %s\nSpoolman : %s  (#%d)\n\nMauvais ID ? Vérifiez-le.",
    "标签:     %s\nSpoolman: %s  (#%d)\n\nID 有误？请再次核对。" },  // STR_WARN_B_DETAILS
  { "Hersteller wählen  (%d Spulen)", "Choose vendor  (%d spools)",
    "Choisir le fabricant  (%d bobines)",
    "选择品牌 (%d 个料盘)" },  // STR_VENDOR_TITLE
  { "Material wählen", "Choose material", "Choisir le matériau", "选择材质" },  // STR_MAT_TITLE
  { "Keine Spulen ohne Tag\nin Spoolman gefunden.",
    "No unlinked spools\nfound in Spoolman.",
    "Aucune bobine sans tag\ntrouvée dans Spoolman.",
    "Spoolman 中未找到\n未绑定的料盘。" },  // STR_NO_VENDORS
  { "Keine Materialien gefunden.", "No materials found.",
    "Aucun matériau trouvé.",
    "未找到材质。" },  // STR_NO_MATERIALS
  { "Keine passenden Spulen.\nBitte per ID verlinken.", "No matching spools.\nPlease link via ID.",
    "Aucune bobine correspondante.\nLiez la bobine par son ID.",
    "无匹配料盘。\n请通过 ID 绑定。" },  // STR_NO_SPOOLS
  { "Verknüpfen?", "Link this spool?",
    "Lier cette bobine ?",
    "绑定此料盘？" },  // STR_CONFIRM_LINK
  { LV_SYMBOL_OK "  Verknüpfen", LV_SYMBOL_OK "  Link",
    LV_SYMBOL_OK "  Lier",
    LV_SYMBOL_OK "  绑定" },  // STR_LINK_OK

  // Tare
  { LV_SYMBOL_WARNING "  Waage nicht bereit",
    LV_SYMBOL_WARNING "  Scale not ready",
    LV_SYMBOL_WARNING "  Balance non prête",
    LV_SYMBOL_WARNING "  秤未就绪" },  // STR_TARE_NOT_READY
  { "API Fehler", "API Error", "Erreur d'API", "API 错误" },  // STR_API_ERROR

  // Reboot popup
  { "Neustart erforderlich", "Restart required", "Redémarrage nécessaire", "需要重启" },  // STR_REBOOT_TITLE
  { "Einstellung wird nach\ndem Neustart aktiv.",
    "Setting takes effect\nafter restart.",
    "Le réglage s'applique après\nle redémarrage.",
    "设置将在重启后\n生效。" },  // STR_REBOOT_MSG
  { LV_SYMBOL_REFRESH "  Jetzt neu starten",
    LV_SYMBOL_REFRESH "  Restart now",
    LV_SYMBOL_REFRESH "  Redémarrer",
    LV_SYMBOL_REFRESH "  立即重启" },  // STR_REBOOT_BTN

  // WiFi quality
  { "Ausgezeichnet", "Excellent",    "Excellent",  "极好" },  // STR_WIFI_QUAL_EXCELLENT
  { "Gut",           "Good",         "Bon",        "良好" },  // STR_WIFI_QUAL_GOOD
  { "Mittel",        "Medium",       "Moyen",      "一般" },  // STR_WIFI_QUAL_MEDIUM
  { "Schwach",       "Weak",         "Faible",     "较弱" },  // STR_WIFI_QUAL_WEAK
  { "Verbunden",     "Connected",    "Connecté",   "已连接" },  // STR_WIFI_STATUS_CONNECTED
  { "Getrennt",      "Disconnected", "Déconnecté", "未连接" },  // STR_WIFI_STATUS_DISCONNECTED

  // Numpad buttons
  { LV_SYMBOL_OK "  Speichern", LV_SYMBOL_OK "  Save", LV_SYMBOL_OK "  Enregistrer",
    LV_SYMBOL_OK "  保存" },  // STR_BTN_SAVE

  // Spool list title
  { "Alle", "All", "Toutes", "全" },  // STR_SPOOLS_ALL

  // Settings calibration sub
  { "Faktor: %.2f", "Factor: %.2f", "Facteur : %.2f", "系数: %.2f" },  // STR_CAL_FACTOR_SHORT

  // Archive confirm
  { "Spule wirklich\narchivieren?", "Really archive\nthis spool?",
    "Voulez-vous vraiment\narchiver cette bobine ?",
    "确定归档\n此料盘？" },  // STR_ARCHIVE_CONFIRM


  // Bag weight current label
  { "Aktuell: %.0f g", "Current: %.0f g", "Actuel : %.0f g", "当前: %.0f g" },  // STR_BAG_CURRENT

  // Warn popup A fields
  { "Spule #%d  |  %s %s\nAkt. Tag: %s",
    "Spool #%d  |  %s %s\nCur. tag: %s",
    "Bobine #%d  |  %s %s\nTag : %s",
    "料盘 #%d  |  %s %s\n当前标签: %s" },  // STR_WARN_A_SPOOL_INFO
  { "Spule #%d\nAkt. Tag: %s",
    "Spool #%d\nCur. tag: %s",
    "Bobine #%d\nTag : %s",
    "料盘 #%d\n当前标签: %s" },  // STR_WARN_A_SPOOL_SHORT

  // Link entry context
  { "%s | nicht in Spoolman", "%s | not in Spoolman", "%s | absente de Spoolman",
    "%s | 不在 Spoolman 中" },  // STR_LINK_CTX_NOT_IN_SM


  // First boot welcome screen
  { "Willkommen!",
    "Welcome!",
    "Bienvenue !",
    "欢迎使用！" },  // STR_FIRSTBOOT_TITLE

  // Extra fields screen
  { "Spoolman Extra-Felder",
    "Spoolman Extra Fields",
    "Champs supplémentaires Spoolman",
    "Spoolman 扩展字段" },  // STR_EXTRA_FIELDS_TITLE
  { "Prüfen...",
    "Checking...",
    "Vérification...",
    "正在检查..." },  // STR_EXTRA_FIELDS_CHECKING
  { LV_SYMBOL_OK "  Vorhanden: %s",
    LV_SYMBOL_OK "  Present: %s",
    LV_SYMBOL_OK "  Présents : %s",
    LV_SYMBOL_OK "  已存在：%s" },  // STR_EXTRA_FIELDS_ALL_OK
  { LV_SYMBOL_WARNING "  Fehlende Felder: %s",
    LV_SYMBOL_WARNING "  Missing fields: %s",
    LV_SYMBOL_WARNING "  Champs manquants : %s",
    LV_SYMBOL_WARNING "  缺少字段：%s" },  // STR_EXTRA_FIELDS_MISSING
  { "Lege Felder an...",
    "Creating fields...",
    "Création des champs...",
    "正在创建字段..." },  // STR_EXTRA_FIELDS_CREATING
  { LV_SYMBOL_WARNING "  Fehler beim Anlegen: %s",
    LV_SYMBOL_WARNING "  Error creating: %s",
    LV_SYMBOL_WARNING "  Échec de la création : %s",
    LV_SYMBOL_WARNING "  创建失败：%s" },  // STR_EXTRA_FIELDS_CREATE_FAIL
  { LV_SYMBOL_WARNING "  Kein WiFi",
    LV_SYMBOL_WARNING "  No WiFi",
    LV_SYMBOL_WARNING "  Pas de WiFi",
    LV_SYMBOL_WARNING "  无 WiFi" },  // STR_EXTRA_FIELDS_NO_WIFI
  { LV_SYMBOL_WARNING "  Kein Spoolman konfiguriert",
    LV_SYMBOL_WARNING "  No Spoolman configured",
    LV_SYMBOL_WARNING "  Aucun Spoolman configuré",
    LV_SYMBOL_WARNING "  未配置 Spoolman" },  // STR_EXTRA_FIELDS_NO_SPOOLMAN

  // Calibration reminder screen
  { "Waage kalibrieren",
    "Calibrate scale",
    "Étalonner la balance",
    "校准秤" },  // STR_CAL_REMINDER_TITLE
  { LV_SYMBOL_EDIT "  Jetzt kalibrieren",
    LV_SYMBOL_EDIT "  Calibrate now",
    LV_SYMBOL_EDIT "  Étalonner",
    LV_SYMBOL_EDIT "  立即校准" },  // STR_CAL_REMINDER_NOW

  // Calibration TARE hint

  // Extra fields test button

  // Spoolman IP validation
  { "Verbindung wird geprüft...",
    "Testing connection...",
    "Test de la connexion...",
    "正在测试连接..." },  // STR_SPOOLMAN_TESTING
  { LV_SYMBOL_WARNING "  Spoolman nicht erreichbar",
    LV_SYMBOL_WARNING "  Spoolman not reachable",
    LV_SYMBOL_WARNING "  Spoolman injoignable",
    LV_SYMBOL_WARNING "  无法连接 Spoolman" },  // STR_SPOOLMAN_FAIL
  { "Erneut versuchen",
    "Retry",
    "Réessayer",
    "重试" },  // STR_SPOOLMAN_RETRY
  { "Überspringen",
    "Skip",
    "Ignorer",
    "跳过" },  // STR_SPOOLMAN_SKIP

  // More info filament screen
  { "Mehr Info",
    "More info",
    "Plus d'infos",
    "更多信息" },  // STR_BTN_MORE_INFO

  // GitHub OTA check screen
  { "GitHub Update",
    "GitHub Update",
    "Mise à jour GitHub",
    "GitHub 更新" },  // STR_GH_OTA_TITLE
  { "Auf Updates prüfen",
    "Check for Updates",
    "Rechercher des mises à jour",
    "检查更新" },  // STR_GH_OTA_CHECK_BTN
  { "Prüfen...",
    "Checking...",
    "Recherche...",
    "正在检查..." },  // STR_GH_OTA_CHECKING
  { "Kein WLAN - bitte zuerst verbinden",
    "No WiFi - please connect first",
    "Pas de WiFi - connectez-vous d'abord",
    "无 WiFi - 请先连接" },  // STR_GH_OTA_NO_WIFI
  { "Bereits aktuell",
    "Already up to date",
    "Déjà à jour",
    "已是最新版本" },  // STR_GH_OTA_UP_TO_DATE
  { "Update verfügbar: %s",
    "Update available: %s",
    "Mise à jour disponible : %s",
    "发现新版本：%s" },  // STR_GH_OTA_UPDATE_AVAIL
  { "Jetzt installieren",
    "Install Now",
    "Installer maintenant",
    "立即安装" },  // STR_GH_OTA_UPDATE_BTN
  { "Installiere... bitte warten",
    "Installing... please wait",
    "Installation... veuillez patienter",
    "正在安装... 请稍候" },  // STR_GH_OTA_FLASHING
  { "Update erfolgreich - startet neu...",
    "Update successful - restarting...",
    "Mise à jour réussie - redémarrage...",
    "更新成功 - 正在重启..." },  // STR_GH_OTA_FLASH_OK
  { "Update fehlgeschlagen",
    "Update failed",
    "Échec de la mise à jour",
    "更新失败" },  // STR_GH_OTA_FLASH_FAIL
  { "Installiert: %s",
    "Installed: %s",
    "Installée : %s",
    "当前版本：%s" },  // STR_GH_OTA_INSTALLED
  { "Vorabversionen",
    "Pre-release",
    "Pré-versions",
    "预览版" },  // STR_GH_OTA_PRERELEASE
  { "Automatisch suchen",
    "Auto check",
    "Recherche auto",
    "自动检查" },  // STR_GH_OTA_AUTOCHECK
  { "Ältere Version verfügbar: %s",
    "Older release available: %s",
    "Version plus ancienne disponible : %s",
    "可用旧版本：%s" },  // STR_GH_OTA_OLDER
  { "Zurückstufen",
    "Downgrade",
    "Rétrograder",
    "降级" },  // STR_GH_OTA_DOWNGRADE_BTN
  { "Auf %s zurückstufen?\nDiese Version ist älter als die installierte.",
    "Downgrade to %s?\nThis release is older than the installed one.",
    "Revenir à %s ?\nCette version est plus ancienne que celle installée.",
    "降级到 %s？\n此版本低于当前已安装版本。" },  // STR_GH_OTA_DOWNGRADE_ASK

  { "Last Used Modus",
    "Last Used Mode",
    "Mode Last Used",
    "最近使用模式" },  // STR_BTN_LASTUSED_MODE
  { "OpenSpoolMan oder SpoolmanScale",
    "OpenSpoolMan or SpoolmanScale",
    "OpenSpoolMan ou SpoolmanScale",
    "OpenSpoolMan 或 SpoolmanScale" },  // STR_BTN_LASTUSED_MODE_SUB
  { "Last Used Modus",
    "Last Used Mode",
    "Mode Last Used",
    "最近使用模式" },  // STR_LASTUSED_TITLE
  { "OpenSpoolMan",
    "OpenSpoolMan",
    "OpenSpoolMan",
    "OpenSpoolMan" },  // STR_LASTUSED_OPT_OSM
  { "Zuletzt gewogen",
    "Last Weighed",
    "Dernière pesée",
    "最近称重" },  // STR_LASTUSED_OPT_WEIGHED
  { "Wird die Nutzung deines Filaments in Spoolman genau getrackt, z.B. automatisch durch OpenSpoolMan beim Bambu Lab Drucker, dann wird auf dem Hauptscreen das Datum der letzten Benutzung aus Spoolman angezeigt.",
    "If your filament usage is tracked in Spoolman, e.g. automatically via OpenSpoolMan with a Bambu Lab printer, the main screen will show the date of the last use from Spoolman.",
    "Si la consommation de votre filament est suivie avec précision dans Spoolman, par exemple automatiquement par OpenSpoolMan avec une imprimante Bambu Lab, l'écran principal affiche la date de dernière utilisation enregistrée dans Spoolman.",
    "若 Spoolman 自动追踪耗材用量（如配合 Bambu 打印机使用 OpenSpoolMan），主屏幕将显示 Spoolman 中的最近使用日期。" },  // STR_LASTUSED_DESC_OSM
  { "Wird das 'Last Used' Feld in Spoolman nicht aktiv von dir genutzt, dann benutzt SpoolmanScale dieses Feld, um das Datum des letzten Gewichtsupdates zu speichern. Der Hauptscreen zeigt dann 'Zuletzt gewogen' statt 'Zuletzt benutzt'.",
    "If you don't actively use the 'Last Used' field in Spoolman, SpoolmanScale will use it to store the date of the last weight update. The main screen will then show 'Last Weighed' instead of 'Last Used'.",
    "Si vous ne vous servez pas du champ 'Last Used' (Dernière utilisation) de Spoolman, SpoolmanScale y inscrit la date de la dernière mise à jour du poids. L'écran principal affiche alors 'Dernière pesée' au lieu de 'Dernier usage'.",
    "若未使用 Spoolman 的“最近使用”字段，SpoolmanScale 将用其记录上次称重日期，主屏幕将显示“最近称重”而非“最近使用”。" },  // STR_LASTUSED_DESC_WEIGHED
  // FilaMan keeps both values itself, so the wording differs from Spoolman:
  // nothing is written, the scale only picks which source it reads.
  { "FilaMan",
    "FilaMan",
    "FilaMan",
    "FilaMan" },  // STR_LASTUSED_OPT_FILAMAN
  { "FilaMan pflegt 'Zuletzt benutzt' selbst und trägt dort echten Druckverbrauch ein, z.B. über seine Druckeranbindung. Solange noch kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "FilaMan maintains 'Last Used' itself and records real print consumption there, e.g. through its printer integration. Until a print has been recorded, the main screen falls back to the last weighing.",
    "FilaMan renseigne lui-même la date de dernière utilisation d'après la consommation réelle des impressions, par exemple via sa connexion à l'imprimante. Tant qu'aucune impression n'est enregistrée, l'écran principal affiche à la place la dernière pesée.",
    "FilaMan 自行维护“上次使用”，并通过打印机联动等方式记录实际打印消耗。在记录到打印前，主屏幕将改用上次称重时间。" },  // STR_LASTUSED_DESC_FILAMAN_USED
  { "FilaMan protokolliert jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen' und damit, wann du die Spule zuletzt in der Hand hattest. Es wird nichts zusätzlich gespeichert.",
    "FilaMan logs every weighing with a timestamp, including the ones from this scale. The main screen then shows 'Last Weighed', i.e. when you last handled the spool. Nothing extra is stored.",
    "FilaMan enregistre la date de chaque pesée, y compris celles faites avec cette balance. L'écran principal affiche alors 'Dernière pesée', c'est-à-dire la dernière fois que vous avez eu la bobine en main. La balance n'écrit rien de plus.",
    "FilaMan 会带时间戳记录每次称重（包括本秤的数据），主屏幕随后显示“上次称重”，即您上次取放料盘的时间。不会额外存储其他信息。" },  // STR_LASTUSED_DESC_FILAMAN_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing",
    "Consommation ou pesée",
    "打印消耗或称重" },  // STR_BTN_LASTUSED_MODE_SUB_FM
  // BamBuddy keeps both dates itself: last_used is stamped when a print
  // consumes the spool, last_weighed_at when a weight is written. Neither is
  // ours to fill, so unlike Spoolman nothing is repurposed here.
  { "BamBuddy",
    "BamBuddy",
    "BamBuddy",
    "BamBuddy" },  // STR_LASTUSED_OPT_BAMBUDDY
  { "BamBuddy trägt 'Zuletzt benutzt' selbst ein, wenn ein Druck von dieser Spule verbraucht. Solange kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "BamBuddy fills 'last used' itself when a print consumes this spool. Until a print has been recorded, the main screen falls back to the last weighing.",
    "BamBuddy renseigne lui-même la date de dernier usage quand une impression consomme du filament de cette bobine. Tant qu'aucune impression n'a été enregistrée, l'écran principal affiche la dernière pesée à la place.",
    "当打印消耗此料盘时，BamBuddy 会自动填写“上次使用”。在记录到打印前，主屏幕将改用上次称重时间。" },  // STR_LASTUSED_DESC_BAMBUDDY_USED
  { "BamBuddy stempelt jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen'. Nur das BamBuddy-Inventar führt dieses Feld - mit einem Spoolman-Server dahinter bleibt es leer.",
    "BamBuddy stamps every weighing, including the ones from this scale. The main screen then shows 'last weighed'. Only the BamBuddy inventory keeps this field - with a Spoolman server behind it, it stays empty.",
    "BamBuddy enregistre la date de chaque pesée, y compris celles faites avec cette balance. L'écran principal affiche alors 'Dernière pesée'. Seul l'inventaire propre à BamBuddy conserve cette date : si BamBuddy s'appuie sur un serveur Spoolman, elle reste vide.",
    "BamBuddy 会为每次称重记录时间戳（包括本秤的数据），主屏幕随后显示“上次称重”。仅 BamBuddy 库存保留此字段，若后端连接 Spoolman 则保持为空。" },  // STR_LASTUSED_DESC_BAMBUDDY_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing",
    "Consommation ou pesée",
    "打印消耗或称重" },  // STR_BTN_LASTUSED_MODE_SUB_BB
  // BamBuddy's own inventory stores consumption and derives the rest, so it
  // cannot hold more filament than the label promises. Asked before writing
  // rather than letting the value snap back on the next scan.
  { "Mehr als das Etikett",
    "More than the label",
    "Dépasse l'étiquette",
    "超出标称重量" },  // STR_BB_CAP_TITLE
  { "Gemessen: %.0f g. Das Etikett sagt %.0f g. Mehr, als das Etikett hergibt, lässt sich nicht speichern - der Rest stünde danach wieder auf voll.",
    "Measured: %.0f g. The label says %.0f g. No more than the label allows can be stored, so the remainder would read as full again.",
    "Mesuré : %.0f g. L'étiquette indique %.0f g. Impossible d'enregistrer plus que l'étiquette : le poids restant serait ramené à celui d'une bobine pleine.",
    "实测：%.0f g。标签标称 %.0f g。存储重量不能超过标称值，否则剩余量将重新显示为满盘。" },  // STR_BB_CAP_BODY
  { "Etikett auf %.0f g anheben",
    "Raise label to %.0f g",
    "Porter l'étiquette à %.0f g",
    "标称改为 %.0f g" },  // STR_BB_CAP_RAISE
  { "Etikett behalten",
    "Keep the label",
    "Garder l'étiquette",
    "保留原标称" },  // STR_BB_CAP_KEEP
  { "Trocknungsdatum",
    "Drying date",
    "Date de séchage",
    "烘干日期" },  // STR_BB_DRIED_TITLE
  { "Nicht speichern",
    "Do not store",
    "Ne pas mémoriser",
    "不保存" },  // STR_BB_DRIED_OFF
  { "Das Datum bleibt leer",
    "The date stays empty",
    "La date reste vide",
    "日期保持为空" },  // STR_BB_DRIED_OFF_SUB
  { "Spoolman hinter BamBuddy",
    "Spoolman behind BamBuddy",
    "Spoolman derrière BamBuddy",
    "BamBuddy 后端 Spoolman" },  // STR_BB_DRIED_SPOOLMAN
  { "In extra.last_dried auf dem Spoolman-Server",
    "Into extra.last_dried on the Spoolman server",
    "Dans extra.last_dried sur le serveur Spoolman",
    "写入 Spoolman 的 extra.last_dried" },  // STR_BB_DRIED_SPOOLMAN_SUB
  { "Nur wenn BamBuddy auf einen Spoolman-Server zeigt",
    "Only when BamBuddy points at a Spoolman server",
    "Si BamBuddy pointe vers un serveur Spoolman",
    "仅当 BamBuddy 指向 Spoolman 时可用" },  // STR_BB_DRIED_SPOOLMAN_NA
  { "Ins Notizfeld",
    "Into the note field",
    "Dans le champ note",
    "写入备注字段" },  // STR_BB_DRIED_NOTE
  { "Als [last_dried:JJJJ-MM-TT] in der Notiz",
    "As [last_dried:YYYY-MM-DD] in the note",
    "[last_dried:AAAA-MM-JJ] dans la note",
    "以 [last_dried:YYYY-MM-DD] 存入备注" },  // STR_BB_DRIED_NOTE_SUB
  { "Neuere BamBuddy-Versionen haben ein eigenes Feld für das Trocknungsdatum, die Waage schreibt dann immer dorthin. Ältere haben keines: Das Notizfeld geht immer und behält den übrigen Text, der andere Weg schreibt in last_dried auf dem Spoolman-Server hinter BamBuddy.",
    "Newer BamBuddy versions have their own field for the drying date, and the scale always writes there. Older ones have none: the note field always works and keeps the rest of the text, the other route writes into last_dried on the Spoolman server behind BamBuddy.",
    "Les versions récentes de BamBuddy ont leur propre champ pour la date de séchage, la balance y écrit alors toujours. Les anciennes n'en ont pas : le champ note fonctionne dans tous les cas et garde le reste du texte, l'option 'Spoolman derrière BamBuddy' écrit dans last_dried, sur le serveur Spoolman relié à BamBuddy.",
    "新版 BamBuddy 自带烘干日期字段，称重台会直接写入该处。旧版无此字段：写入备注始终有效且保留原有内容；另一方式则写入后端 Spoolman 的 last_dried 字段。" },  // STR_BB_DRIED_INFO
  // Short forms for the connection test line, which has room for about 34
  // characters. The "Inventar:" prefix is what says this names the data
  // source and not the backend - bare "Spoolman" always means the native one.
  { "Inventar: BamBuddy",
    "Inventory: BamBuddy",
    "Inventaire : BamBuddy",
    "库存：BamBuddy" },  // STR_BB_INV_OWN
  { "Inventar: Spoolman",
    "Inventory: Spoolman",
    "Inventaire : Spoolman",
    "库存：Spoolman" },  // STR_BB_INV_SPOOLMAN
  // Label above the database name on the backend screen. Same word as the
  // short form above, so the two places do not invent two vocabularies.
  { "Inventar",
    "Inventory",
    "Inventaire",
    "库存" },  // STR_BACKEND_INVENTORY

  // AMS view. The unit names are built here rather than taken from the
  // server: both backends generate their own "AMS A" style labels, and a
  // generated English label would land on the screen untranslated.
  { "AMS-Status",
    "AMS status",
    "État de l'AMS",
    "AMS 状态" },  // STR_AMSV_TITLE
  { "AMS ansehen",
    "Show the AMS",
    "Voir l'AMS",
    "查看 AMS" },  // STR_AMSV_BTN
  { "Fächer des Druckers",
    "The printer's bays",
    "Les bacs de l'imprimante",
    "打印机槽位" },  // STR_AMSV_BTN_SUB
  { "Neu laden",
    "Reload",
    "Recharger",
    "刷新" },  // STR_AMSV_RELOAD
  { "AMS wird gelesen...",
    "Reading the AMS...",
    "Lecture de l'AMS...",
    "正在读取 AMS..." },  // STR_AMSV_LOADING
  { "AMS %d",
    "AMS %d",
    "AMS %d",
    "AMS %d" },  // STR_AMSV_UNIT
  { "AMS HT %d",
    "AMS HT %d",
    "AMS HT %d",
    "AMS HT %d" },  // STR_AMSV_UNIT_HT
  { "Extern",
    "External",
    "Externe",
    "外挂料架" },  // STR_AMSV_UNIT_EXT
  { "Leer",
    "Empty",
    "Vide",
    "空" },  // STR_AMSV_EMPTY
  { "%d%%",
    "%d%%",
    "%d%%",
    "%d%%" },  // STR_AMSV_HUM_PCT
  { "Stufe %d",
    "Step %d",
    "Niveau %d",
    "等级 %d" },  // STR_AMSV_HUM_LEVEL
  // Says why the bays are still there. FilaMan keeps the assignment in its
  // database but temperature and humidity are live MQTT readings, so an
  // unreachable printer shows full bays with no climate - which looks like a
  // fault in the scale unless the line explains it.
  { "offline, letzter Stand",
    "offline, last known state",
    "hors ligne, dernier état",
    "离线，显示上次状态" },  // STR_AMSV_OFFLINE
  // Not the same as offline: the server has simply never heard from its
  // driver. Saying "offline" there blames the printer for the server.
  { "Status unbekannt",
    "state unknown",
    "état inconnu",
    "状态未知" },  // STR_AMSV_UNKNOWN
  { "Kein AMS gemeldet",
    "No AMS reported",
    "Aucun AMS signalé",
    "未检测到 AMS" },  // STR_AMSV_NO_AMS
  { "Kein Drucker gefunden",
    "No printer found",
    "Aucune imprimante trouvée",
    "未找到打印机" },  // STR_AMSV_NO_PRINTER
  { "Server antwortet %d",
    "The server answers %d",
    "Le serveur répond %d",
    "服务器返回 %d" },  // STR_AMSV_ERR_HTTP
  { "Kein Netz",
    "No network",
    "Pas de réseau",
    "无网络" },  // STR_AMSV_ERR_NET
  { "Zu wenig Speicher für alle Fächer",
    "Not enough memory for every bay",
    "Mémoire insuffisante pour tous les bacs",
    "内存不足，无法加载全部槽位" },  // STR_AMSV_ERR_FULL
  { "Trocknet %d °C, %d min",
    "Drying %d °C, %d min",
    "Séchage %d °C, %d min",
    "烘干中 %d °C，%d 分钟" },  // STR_AMSV_DRYING_TIME
  { "Trocknet %d °C",
    "Drying %d °C",
    "Séchage %d °C",
    "烘干中 %d °C" },  // STR_AMSV_DRYING_TEMP
  { "druckt %d%%",
    "printing %d%%",
    "imprime %d%%",
    "打印中 %d%%" },  // STR_AMSV_JOB
  // The printer's own states, in words. Bambu keeps the last job and its
  // 100 % on the wire after a print until the next one starts, so the
  // percentage alone would read "printing 100%" for days.
  { "pausiert bei %d%%",
    "paused at %d%%",
    "en pause à %d%%",
    "已暂停 %d%%" },  // STR_AMSV_JOB_PAUSED
  { "Druck fertig",
    "print finished",
    "impression terminée",
    "打印完成" },  // STR_AMSV_STATE_FINISH
  { "Druck abgebrochen",
    "print failed",
    "impression échouée",
    "打印失败" },  // STR_AMSV_STATE_FAILED
  { "bereit",
    "idle",
    "prête",
    "空闲" },  // STR_AMSV_STATE_IDLE
  { "bereitet vor",
    "preparing",
    "en préparation",
    "准备中" },  // STR_AMSV_STATE_PREPARE
  // Which of several printers is on screen. Same in both languages, but
  // it goes through T() so a language that numbers differently can change it.
  { "%d/%d",
    "%d/%d",
    "%d/%d",
    "%d/%d" },  // STR_AMSV_PRN_OF
  { "%s -> in welches Fach?",
    "%s -> into which bay?",
    "%s -> dans quel bac ?",
    "%s -> 放入哪个槽位？" },  // STR_AMSV_PICK_HEAD
  { "Spule ist zugeordnet",
    "The spool is assigned",
    "La bobine est affectée",
    "料盘已分配" },  // STR_AMSV_ASSIGNED
  { "Spule umgezogen",
    "The spool moved",
    "La bobine a changé de bac",
    "料盘已移动" },  // STR_AMSV_MOVED
  { "Zuordnung fehlgeschlagen",
    "Assignment failed",
    "Échec de l'affectation",
    "分配失败" },  // STR_AMSV_ASSIGN_FAIL
  { "Nach dem Wiegen ins AMS",
    "Into the AMS after weighing",
    "Vers l'AMS après la pesée",
    "称重后放入 AMS" },  // STR_BBAMS_ASK
  { "Beim Abheben nach dem Fach fragen",
    "Ask for the bay on removal",
    "Demander le bac au retrait",
    "取走时询问目标槽位" },  // STR_BBAMS_ASK_SUB
  { "An: nach dem Wiegen einer bekannten Spule fragt die Waage beim Abheben, in welches AMS-Fach sie geht, und trägt das in BamBuddy ein.\n\nBamBuddy konfiguriert das Fach dabei über MQTT am Drucker mit - Material, Farbe und Temperaturen. Das ist gewollt, aber es wirkt auf den Drucker, nicht nur auf die Datenbank.",
    "On: after a known spool has been weighed, the scale asks on removal which AMS bay it goes into and records that in BamBuddy.\n\nBamBuddy also configures the bay on the printer over MQTT while doing so - material, colour and temperatures. That is intended, but it acts on the printer, not only on the database.",
    "Activé : quand vous retirez une bobine connue après sa pesée, la balance demande dans quel bac AMS vous la placez, puis l'enregistre dans BamBuddy.\n\nBamBuddy configure alors aussi ce bac sur l'imprimante par MQTT : matériau, couleur et températures. C'est voulu, mais cela agit sur l'imprimante, pas seulement sur la base de données.",
    "开启：已知料盘称重后，在取走时会询问要放入哪个 AMS 槽位并记录到 BamBuddy。\n\n同时 BamBuddy 会通过 MQTT 配置打印机上的对应槽位（耗材、颜色及温度）。此操作直接作用于打印机，而不仅限于数据库。" },  // STR_BBAMS_ASK_INFO
  { "Werkseinstellungen", "Factory Reset", "Réinitialisation",
    "恢复出厂" },  // STR_BTN_FACTORY_RESET
  { "Alle Einstellungen löschen", "Erase all settings", "Effacer tous les réglages",
    "清除所有设置" },  // STR_BTN_FACTORY_RESET_SUB
  { "Werkseinstellungen?", "Factory Reset?", "Réinitialiser ?",
    "恢复出厂设置？" },  // STR_FACTORY_RESET_TITLE
  { "Alle Einstellungen werden gelöscht:\nWLAN, Server-Adresse, Kalibrierung,\nSprache und alle anderen Daten.\nDanach startet das Gerät neu.",
    "All settings will be erased:\nWiFi, server address, calibration,\nlanguage and all other data.\nThe device will restart afterwards.",
    "Tous les réglages seront effacés :\nWiFi, adresse du serveur, étalonnage,\nlangue et toutes les autres données.\nL'appareil redémarre ensuite.",
    "将清除所有设置：\nWiFi、服务器地址、校准数据、\n语言及其他所有数据。\n随后设备将重启。" },  // STR_FACTORY_RESET_MSG
  { "Ja, alles löschen", "Yes, erase everything", "Oui, tout effacer",
    "确定全部清除" },  // STR_FACTORY_RESET_CONFIRM
  { "Neu / Kopie",           "New / Copy",            "Nouveau / Copie",       "新建/复制" },  // STR_BTN_COPY_SPOOL
  { "Spule kopieren",        "Copy spool",            "Copier la bobine",      "复制料盘" },  // STR_COPY_TITLE
  { "Spoolman-ID eingeben",  "Enter Spoolman ID",     "Saisir l'ID Spoolman",  "输入 Spoolman ID" },  // STR_COPY_ID_BTN
  { "Aktive Spulen",         "Active spools",         "Bobines actives",       "在用料盘" },  // STR_COPY_ACTIVE_BTN
  { "Archivierte Spulen",    "Archived spools",       "Bobines archivées",     "已归档料盘" },  // STR_COPY_ARCHIVED_BTN
  { "Neue Spule anlegen?",   "Create new spool?",     "Créer une bobine ?",    "创建新料盘？" },  // STR_COPY_CONFIRM_TITLE
  { "Spule erstellt!",       "Spool created!",        "Bobine créée !",        "料盘已创建！" },  // STR_COPY_OK
  { "Fehler beim Erstellen", "Error creating spool",  "Échec de la création",  "创建料盘失败" },  // STR_COPY_FAIL
  { "Keine Spulen gefunden", "No spools found",       "Aucune bobine trouvée", "未找到料盘" },  // STR_COPY_NO_SPOOLS
  { "Unlink",                "Unlink",                "Dissocier",             "解绑" },  // STR_UNLINK_BTN
  { "Spule unlinken?",       "Unlink spool?",         "Dissocier la bobine ?", "解绑料盘？" },  // STR_UNLINK_TITLE
  { "Löscht den Eintrag im Tag-Feld in Spoolman.\nDie Spule bleibt erhalten.",
    "Clears the tag field entry in Spoolman.\nThe spool itself is kept.",
    "Efface l'entrée du champ tag dans Spoolman.\nLa bobine elle-même est conservée.",
    "将清除 Spoolman 中的标签字段。\n料盘记录本身会保留。" },  // STR_UNLINK_MSG
  { "Ja, unlinken", "Yes, unlink",
    "Oui, dissocier",
    "确定解绑" },  // STR_UNLINK_CONFIRM
  { "Verbinde mit WLAN...", "Connecting to WiFi...",
    "Connexion au WiFi...",
    "正在连接 WiFi..." },  // STR_WIFI_CONNECTING_BOOT
  { "Gerät wird gestartet...", "Starting up, please wait...",
    "Démarrage de l'appareil...",
    "正在启动，请稍候..." },  // STR_BOOTING
  { "Neustart", "Reboot",
    "Redémarrer",
    "重启" },  // STR_BTN_REBOOT
  { "Gerät neu starten", "Restart device",
    "Redémarrer l'appareil",
    "重新启动设备" },  // STR_BTN_REBOOT_SUB
  { "Ganze Gramm", "Whole grams",
    "Grammes entiers",
    "整数克" },  // STR_WHOLE_GRAM
  { "Mehr Spulen gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More spools found - not listed? Use Spool-ID",
    "Liste incomplète - bobine absente ? Liez-la par son ID",
    "还有更多料盘 - 未列出？请用料盘 ID" },  // STR_LIST_MORE_SPOOLS
  { "Mehr Hersteller gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More vendors found - not listed? Use Spool-ID",
    "Liste incomplète - fabricant absent ? Liez par l'ID de bobine",
    "还有更多品牌 - 未列出？请用料盘 ID" },  // STR_LIST_MORE_VENDORS
  { "Mehr Materialien gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More materials found - not listed? Use Spool-ID",
    "Liste incomplète - matériau absent ? Liez par l'ID de bobine",
    "还有更多材质 - 未列出？请用料盘 ID" },  // STR_LIST_MORE_MATS

  // Auto-Weight: the help text behind the switch in the scale menu
  { "Liegt eine erkannte Spule 4 Sekunden still, wird ihr Gewicht ohne Beutel gesendet. Unter 1 g Änderung wird nichts gesendet. Ist sie mehr als 5 g schwerer als gespeichert, sendet die Waage nicht und fragt nach.",
    "When a recognised spool lies still for 4 seconds, its weight is sent, without the bag. Under 1 g of change nothing is sent. If it is more than 5 g heavier than stored, the scale sends nothing and asks.",
    "Quand une bobine reconnue reste immobile 4 secondes, son poids est envoyé, sans le sachet. En dessous de 1 g de différence, rien n'est envoyé. Si elle pèse plus de 5 g de plus que la valeur enregistrée, la balance n'envoie rien et demande.",
    "已识别料盘静置 4 秒后自动发送净重（不含包装袋）。变化小于 1 g 不发送；若比记录重 5 g 以上则不发送并弹窗确认。" },  // STR_AUTO_WEIGHT_INFO
  { "Lagerort",
    "Location",
    "Emplacement",
    "存放位置" },  // STR_BTN_LOCATION
  { "Lagerort wählen",
    "Select location",
    "Choisir l'emplacement",
    "选择位置" },  // STR_LOCATION_TITLE
  { LV_SYMBOL_CLOSE " Kein Lagerort",
    LV_SYMBOL_CLOSE " No location",
    LV_SYMBOL_CLOSE " Aucun emplacement",
    LV_SYMBOL_CLOSE " 无位置" },  // STR_LOCATION_NONE
  { "Lade...",
    "Loading...",
    "Chargement...",
    "加载中..." },  // STR_LOCATION_LOADING
  { "Kein WLAN",
    "No WiFi",
    "Pas de WiFi",
    "无 WiFi" },  // STR_LOCATION_NO_WIFI
  { "Keine Spoolman-Lagerorte gefunden",
    "No Spoolman locations found",
    "Aucun emplacement Spoolman trouvé",
    "未找到 Spoolman 位置" },  // STR_LOCATION_NO_LOCATIONS
  { "Leere Lagerorte werden nicht angezeigt",
    "Empty locations are not shown",
    "Les emplacements vides ne sont pas affichés",
    "不显示空位置" },  // STR_LOCATION_HINT_EMPTY
  { "Zu viele Lagerorte - nicht alle angezeigt",
    "Too many locations - not all shown",
    "Trop d'emplacements - tous ne sont pas affichés",
    "位置过多 - 未全部显示" },  // STR_LOCATION_LIMIT_HIT
  { "Ortsabfrage bei Entnahme", "Location on removal",
    "Demander l'emplacement au retrait",
    "取下询问位置" },  // STR_BTN_AUTO_LOC_POPUP
  { "Trocknungserinnerung", "Drying Reminder", "Rappel de séchage", "烘干提醒" },  // STR_BTN_DRYING_REMINDER
  { "Trocknungserinnerung", "Drying Reminder", "Rappel de séchage", "烘干提醒" },  // STR_DRYING_REMINDER_TITLE

  // Drying Reminder Screen
  { "Aus",      "Off",      "Désactivé", "关" },  // STR_DRY_MODE_OFF
  { "Material", "Material", "Matériau",  "按材质" },  // STR_DRY_MODE_MATERIAL
  { "Manuell",  "Manual",   "Manuel",    "手动" },  // STR_DRY_MODE_MANUAL
  { "Kein Ampelsignal aktiv.\n\nMaterial: Schwellwerte pro Filamenttyp\n(konfigurierbar im Browser).\n\nManuell: Eigene Grenzwerte in Tagen.",
    "No alert signal active.\n\nMaterial: Thresholds per filament type\n(configurable in browser).\n\nManual: Custom limits in days.",
    "Aucun code couleur (vert, jaune, rouge).\n\nMatériau : seuils par type de filament\n(réglables dans le navigateur).\n\nManuel : vos propres seuils, en jours.",
    "提示灯已关闭。\n\n按材质：按耗材类型设阈值\n（可在浏览器配置）。\n\n手动：自定义天数上限。" },  // STR_DRY_OFF_DESC
  { "Schwellwerte im Browser editierbar.", "Thresholds editable in browser.",
    "Seuils modifiables dans le navigateur.",
    "阈值可在浏览器编辑。" },  // STR_DRY_MAT_HINT
  { "Material", "Material",
    "Matériau",
    "材质" },  // STR_DRY_MAT_HDR_MAT
  { "Gelb (Tage)", "Yellow (days)",
    "Jaune (jours)",
    "黄灯(天)" },  // STR_DRY_MAT_HDR_YELLOW
  { "Rot (Tage)", "Red (days)",
    "Rouge (jours)",
    "红灯(天)" },  // STR_DRY_MAT_HDR_RED
  { "Gelb ab", "Yellow from",
    "Jaune dès",
    "黄灯起始" },  // STR_DRY_MAN_YELLOW_LBL
  { "Rot ab", "Red from",
    "Rouge dès",
    "红灯起始" },  // STR_DRY_MAN_RED_LBL
  { "Tippen zum Bearbeiten", "Tap to edit",
    "Touchez pour modifier",
    "点击编辑" },  // STR_DRY_MAN_EDIT_HINT
  { "Grenzwerte gelten für alle Materialien.", "Limits apply to all materials.",
    "Ces seuils s'appliquent à tous les matériaux.",
    "阈值适用于所有材质。" },  // STR_DRY_MAN_INFO
  { "Tage", "days",
    "jours",
    "天" },  // STR_DRY_DAYS_UNIT
  { "Gelb-Schwellwert", "Yellow threshold",
    "Seuil jaune",
    "黄灯阈值" },  // STR_DRY_NUMPAD_YELLOW_TITLE
  { "Rot-Schwellwert", "Red threshold",
    "Seuil rouge",
    "红灯阈值" },  // STR_DRY_NUMPAD_RED_TITLE
  { "Effektive Werte (%.1fx Multiplikator eingerechnet)", "Effective values (%.1fx multiplier included)",
    "Valeurs effectives (facteur sous vide %.1fx inclus)",
    "实际值（已含 %.1fx 倍率）" },  // STR_DRY_MAT_EFF_NOTE
  { "Versiegelt", "Sealed",
    "Sous vide",
    "密封" },  // STR_DRY_SEALED_HDR

  // Backend selection. "Spoolman" and "FilaMan" are product names and stay
  // untranslated, so they are not in this table.
  // "Server" described the technology, not the purpose. Both Spoolman and
  // FilaMan manage a filament inventory, and that is what the user picks
  // here. The address screen keeps "Server", because a server address is
  // literally what gets typed in there.
  { "Filamentverwaltung", "Filament manager", "Gestion du filament", "耗材管理服务" },  // STR_BACKEND_TITLE
  { "Adresse",            "Address",          "Adresse",             "地址" },  // STR_BACKEND_ADDRESS
  { "API-Key",            "API key",          "Clé d'API",           "API密钥" },  // STR_BACKEND_APIKEY
  { "Device-Token",       "Device token",     "Jeton d'appareil",    "设备令牌" },  // STR_BACKEND_DEVICE_TOKEN
  { "gesetzt",            "set",              "en mémoire",          "已设置" },  // STR_BACKEND_SET
  { "fehlt",              "missing",          "à définir",           "未设置" },  // STR_BACKEND_MISSING

  // Web interface. The same server serves the firmware upload and the
  // FilaMan credentials, so the screen title stays neutral.
  { "Weboberfläche",         "Web interface",     "Interface web",      "Web 界面" },  // STR_WEB_TITLE
  { "Im Browser einrichten", "Set up in browser", "Config. navigateur", "在浏览器设置" },  // STR_BTN_WEB_SETUP
  { "Weiter",                "Next",              "Suivant",            "下一步" },  // STR_BTN_NEXT
  // Shown instead of a spool count when the server answered but the number
  // could not be asked for yet, which is the normal FilaMan setup case.
  { "AN",                "ON",              "ON",         "开" },  // STR_ON
  { "AUS",               "OFF",             "OFF",        "关" },  // STR_OFF
  { "Im Browser öffnen", "Open in browser", "Navigateur", "在浏览器打开" },  // STR_BTN_OPEN_BROWSER
  // Names every product in both languages and in every backend mode. Not
  // passed through backendText(), see the comment at the call site.
  { "Nicht mit Spoolman, FilaMan oder BamBuddy verbunden",
    "Not affiliated with Spoolman, FilaMan or BamBuddy",
    "Sans lien avec Spoolman, FilaMan ou BamBuddy",
    "与 Spoolman、FilaMan 或 BamBuddy 无关" },  // STR_NOT_AFFILIATED
  { "Kein Tag erkannt, bitte neu auflegen",
    "No tag detected, place it again",
    "Aucun tag détecté, reposez-le",
    "未检测到标签，请重新放置" },  // STR_LINK_NO_TAG

  // Main screen weight box and More-info detail grid
  { "Waage - Spule",     "Scale - Spool",        "Balance - Bobine",   "秤 - 料盘" },  // STR_LBL_SCALE_SPOOL_CAP
  { "Gesamt",            "Total",                "Total",              "总重" },  // STR_LBL_TOTAL_CAP
  { "o. Beutel",         "w/o bag",              "s. sachet",          "不含包装袋" },  // STR_LBL_WO_BAG_CAP
  { "Farbe",             "Hex Color",            "Couleur",            "颜色代码" },  // STR_LBL_HEX_COLOR
  { "Produktionsdatum",  "Production date",      "Date de production", "生产日期" },  // STR_LBL_PRODUCTION_DATE
  { "Artikelnr.",        "Article no.",          "Réf. article",       "货号" },  // STR_LBL_ARTICLE_NO_SHORT
  { "Leergewicht Spule", "Spool weight (empty)", "Poids bobine vide",  "空盘重量" },  // STR_LBL_SPOOL_WEIGHT_EMPTY

  // Status bar address selector
  { "Im Statusbalken zeigen", "Show in status bar", "Afficher dans la barre d'état",
    "在状态栏显示" },  // STR_BTN_IP_STATUSBAR
  { "Gerät",                  "Device",             "Appareil",                      "设备" },  // STR_IP_BAR_DEVICE

  // Remote link. Deliberately not passed through backendText(): this only
  // ever happens in FilaMan mode, so naming it outright is clearer than a
  // substitution that can never differ.
  { "FilaMan: Spule verknüpfen?", "FilaMan: link spool?", "FilaMan : lier la bobine ?",
    "FilaMan：绑定料盘？" },  // STR_REMOTE_LINK_TITLE
  { "Aufliegenden Tag mit dieser Spule verknüpfen?",
    "Link the tag on the scale to this spool?",
    "Lier le tag posé sur la balance à cette bobine ?",
    "将秤上的标签绑定到此料盘？" },  // STR_REMOTE_LINK_QUESTION
  { "Verknüpfen", "Link", "Lier",
    "绑定" },  // STR_REMOTE_LINK_CONFIRM
  { "Details nicht abrufbar", "Details unavailable", "Détails indisponibles",
    "无法获取详情" },  // STR_REMOTE_LINK_NO_DETAILS
  { "Verknüpfung abgelaufen", "Link request timed out", "Demande de liaison expirée",
    "绑定请求超时" },  // STR_REMOTE_LINK_TIMEOUT

  // Tag versus spool comparison
  { "Tag",      "Tag",      "Tag",      "Tag" },  // STR_REMOTE_LINK_COL_TAG
  { "Spule",    "Spool",    "Bobine",   "料盘" },  // STR_REMOTE_LINK_COL_SPOOL
  { "Material", "Material", "Matériau", "材质" },  // STR_REMOTE_LINK_ROW_MATERIAL
  { "Farbe",    "Colour",   "Couleur",  "颜色" },  // STR_REMOTE_LINK_ROW_COLOR

  // FilaMan options sub screen
  { "Weitere Optionen",        "More options",       "Autres options",      "更多选项" },  // STR_BTN_MORE_OPTIONS
  { "Mehrere Tags verknüpfen", "Link multiple tags", "Lier plusieurs tags", "绑定多个标签" },  // STR_CU_WRITE
  { "Schreibt in Spoolmans Feld card_uids",
    "Writes to Spoolman's card_uids field",
    "Écrit dans le champ card_uids de Spoolman",
    "写入 Spoolman 的 card_uids 字段" },  // STR_CU_WRITE_SUB
  { "An: eine gescannte UID kommt an die Liste, statt sie zu ersetzen. "
    "Verknüpfte Spulen erscheinen wieder in der Verlinken-Liste, damit ein "
    "zweites Tag dazukommen kann.\n\n"
    "Aus: in card_uids steht immer nur eine UID.\n\n"
    "Nur für card_uids, weil es als einziges Extra-Feld eine Liste aufnimmt. "
    "Spoolman NFC kann mehrere Tags von Haus aus und braucht den Schalter "
    "nicht.",
    "On: a scanned UID is appended to the list instead of replacing it. Linked "
    "spools show up in the link list again so a second tag can join them.\n\n"
    "Off: card_uids only ever holds one UID.\n\n"
    "card_uids only, because it is the one extra field that holds a list. "
    "Spoolman NFC does several tags natively and needs no switch.",
    "Activé : un UID scanné s'ajoute à la liste au lieu de la remplacer. Les bobines déjà liées restent proposées au moment de lier, pour pouvoir leur ajouter un second tag.\n\nDésactivé : card_uids contient toujours un seul UID.\n\nCe réglage ne concerne que card_uids, seul champ supplémentaire qui accepte une liste. Spoolman NFC gère plusieurs tags de lui-même et n'en a pas besoin.",
    "开启：扫描到的 UID 会追加到列表而非覆盖。已绑定料盘会再次显示在绑定列表中，以便添加第二个标签。\n\n关闭：card_uids 仅保留单个 UID。\n\n仅适用于 card_uids，因它是唯一支持列表的自定义字段。Spoolman NFC 原生支持多标签，无需此开关。" },  // STR_CU_WRITE_INFO
  { "UID nicht hinzugefügt", "UID not added", "UID non ajouté", "未添加 UID" },  // STR_CU_NOT_WRITTEN
  { "Tag hängt schon an Spule #%d", "Tag already on spool #%d",
    "Ce tag est déjà sur la bobine #%d",
    "标签已绑定至料盘 #%d" },  // STR_TAG_ON_OTHER_SPOOL
  { LV_SYMBOL_WARNING "  Spule hat schon UIDs",
    LV_SYMBOL_WARNING "  Spool already has UIDs",
    LV_SYMBOL_WARNING "  La bobine a déjà des UID",
    LV_SYMBOL_WARNING "  料盘已有 UID" },  // STR_WARN_A_ADD_TITLE
  { "Spule #%d  |  %s %s\nHat bereits %d UID(s)",
    "Spool #%d  |  %s %s\nAlready has %d UID(s)",
    "Bobine #%d  |  %s %s\nPorte déjà %d UID",
    "料盘 #%d  |  %s %s\n已有 %d 个 UID" },  // STR_WARN_A_ADD_INFO
  { "Spule #%d\nHat bereits %d UID(s)",
    "Spool #%d\nAlready has %d UID(s)",
    "Bobine #%d\nPorte déjà %d UID",
    "料盘 #%d\n已有 %d 个 UID" },  // STR_WARN_A_ADD_SHORT
  { "UID hinzufügen", "Add UID", "Ajouter l'UID", "添加 UID" },  // STR_BTN_ADD_UID
  { "Diese Spule ist mehrfach gebunden.\nNur das Tag auf der Waage lösen\noder die ganze Bindung?",
    "This spool is bound more than once.\nRemove only the tag on the scale\nor the whole binding?",
    "Cette bobine est liée plusieurs fois.\nDissocier le tag sur la balance\nou toute la liaison ?",
    "此料盘已绑定多个标签。\n仅解绑秤上的标签，\n还是解除全部绑定？" },  // STR_UNLINK_MULTI_MSG
  { "Nur dieses Tag",            "Only this tag",       "Ce tag seulement",   "仅此标签" },  // STR_BTN_UNLINK_ONE
  { "Alle lösen",                "Unlink all",          "Tout dissocier",     "全部解绑" },  // STR_BTN_UNLINK_ALL
  { "Ohne Nachfrage verknüpfen", "Link without asking", "Lier sans demander", "直接绑定不询问" },  // STR_FLM_AUTOLINK
  { "wenn die Spule schon aufliegt", "when the spool is already on",
    "si la bobine est déjà posée",
    "当料盘已放在秤上时" },  // STR_FLM_AUTOLINK_SUB
  { " (Filament)",   " (filament)", " (filament)",  " (耗材)" },  // STR_TARE_FROM_FILAMENT
  { " (Hersteller)", " (brand)",    " (fabricant)", " (品牌)" },  // STR_TARE_FROM_BRAND
  { "Ohne Beutel wiegen - sonst %.0f g zu viel",
    "Weigh without the bag - %.0f g too much otherwise",
    "Pesez sans le sachet - sinon %.0f g de trop",
    "请去掉包装袋称重 - 否则重 %.0f g" },  // STR_SPOOL_WEIGHT_BAG_HINT
  { "Ohne Tag wiegen", "Weigh without a tag", "Peser sans tag", "无标签称重" },  // STR_FLM_TAGLESS
  { "wenn kein Tag aufgelegt wird", "when no tag is presented",
    "si aucun tag n'est présenté",
    "未刷标签时启用" },  // STR_FLM_TAGLESS_SUB
  { "Spule gewählt - jetzt wiegen", "Spool selected - weigh it now",
    "Bobine choisie - pesez-la",
    "已选料盘 - 请立即称重" },  // STR_REMOTE_LINK_WEIGH
  { LV_SYMBOL_EYE_CLOSE "  Bildschirm aus nach (Min.)",
    LV_SYMBOL_EYE_CLOSE "  Screen off after (min.)",
    LV_SYMBOL_EYE_CLOSE "  Écran éteint après (min)",
    LV_SYMBOL_EYE_CLOSE "  息屏时间 (分钟)" },  // STR_SCREENOFF_LABEL
  { "Nie", "Never", "Jamais", "永不" },  // STR_SCREENOFF_NEVER
  { "Löst FilaMan eine Verknüpfung aus und die Spule liegt schon auf der Waage, wird ohne Rückfrage verknüpft. Passen Material oder Farbe nicht zusammen, fragt die Waage trotzdem nach.",
    "When FilaMan triggers a link and the spool is already on the scale, it is linked without asking. If the material or colour do not match, the scale asks anyway.",
    "Quand une liaison est lancée depuis FilaMan alors que la bobine est déjà sur la balance, la liaison se fait sans confirmation. Si le matériau ou la couleur du tag ne correspondent pas à la bobine choisie, la balance demande quand même.",
    "当 FilaMan 触发绑定且料盘已在秤上时，将直接绑定而不再询问。若耗材材质或颜色不匹配，秤仍会弹窗确认。" },  // STR_FLM_AUTOLINK_INFO
  { "Wird nach einer Verknüpfung aus FilaMan innerhalb von 10 Sekunden kein Tag aufgelegt, lädt die Waage die dort gewählte Spule trotzdem und zeigt sie an. Gewogen wird sie danach wie jede andere: bei eingeschalteter Automatik von selbst, sonst über den Gewichtsknopf. FilaMans eigener Dialog meldet dabei einen Fehler, weil dort kein Tag geschrieben wurde - geladen ist die Spule trotzdem. Auf einen Tag wird nie etwas geschrieben, und die Zuordnung endet, sobald die Spule wieder heruntergenommen wird.",
    "If no tag is presented within 10 seconds of a link from FilaMan, the scale loads the spool chosen there anyway and shows it. Weighing then works as for any other spool: on its own when automatic weighing is on, otherwise through the weight button. FilaMan's own dialog reports an error because no tag was written there - the spool is loaded regardless. Nothing is ever written to a tag, and the spool is released as soon as it is taken off the pad.",
    "Si aucun tag n'est posé dans les 10 secondes qui suivent une liaison lancée depuis FilaMan, la balance charge quand même la bobine choisie dans FilaMan et l'affiche. La pesée se fait ensuite comme pour toute autre bobine : toute seule si la pesée automatique est activée, sinon avec le bouton Envoyer le poids. FilaMan affiche de son côté une erreur, puisqu'aucun tag n'a été écrit, mais la bobine est bien chargée. Rien n'est jamais écrit sur un tag, et cette association temporaire prend fin dès que la bobine est retirée de la balance.",
    "若 FilaMan 触发绑定后 10 秒内未刷标签，秤仍会加载并显示所选料盘。随后的称重方式与常规料盘一致：开启自动称重时自动记录，否则需按称重按钮。此时 FilaMan 弹窗会因未写入标签而报错，但料盘实际已加载。系统不会向标签写入任何数据，且料盘一离开秤盘即解除绑定。" },  // STR_FLM_TAGLESS_INFO

  // Auto AMS assignment. FilaMan marks a freshly weighed spool as pending on
  // every printer driver for a few seconds, so the next tray to be loaded
  // gets it. The wording avoids "auto assign" on its own because the whole
  // point of the ask mode is that it is not automatic.
  { "Auto AMS-Zuordnung", "Auto AMS assign", "Affectation AMS auto", "AMS 自动分配" },  // STR_AMS_TITLE
  { "Spule beim Einlegen zuordnen", "assign the spool as it goes in",
    "affecter la bobine à l'insertion",
    "放入料盘时自动分配槽位" },  // STR_AMS_SUB
  { "FilaMan merkt eine gewogene Spule einige Sekunden vor. Wer in dieser Zeit ein AMS-Fach belädt, bekommt sie zugeordnet. Geöffnet wird das Fenster nur von einem Gewicht, deshalb bucht die Waage beim Zuordnen ein zweites Mal: die Messung steht dann doppelt im Protokoll, der Wert bleibt gleich. Wandert die Spule ohnehin gleich in den Drucker, genügt kurz auflegen.",
    "FilaMan reserves a weighed spool for a few seconds. Whoever loads an AMS tray in that time gets it assigned. Only a weight opens that window, so assigning books the value a second time: the measurement then shows twice in the log, the value stays the same. If the spool is going into the printer anyway, just resting it on the pad is enough.",
    "FilaMan réserve une bobine pesée pendant quelques secondes : si un bac AMS est chargé pendant cette fenêtre, la bobine lui est affectée. Seul un envoi de poids ouvre la fenêtre : pour affecter la bobine, la balance renvoie donc son poids, qui figure alors deux fois dans l'historique FilaMan, avec la même valeur. Si la bobine va de toute façon tout de suite dans l'imprimante, il suffit de la poser un instant sur la balance.",
    "FilaMan 会将刚称重的料盘预留几秒，在此期间装入 AMS 槽位即可自动分配。因仅在记录重量时触发该窗口，分配时会再次提交重量：日志中会显示两条记录，但数值不变。若料盘本就要放入打印机，只需在秤盘上轻放一下即可。" },  // STR_AMS_INFO
  { "Aus",        "Off", "Désactivé", "关闭" },  // STR_AMS_MODE_OFF
  { "Nachfragen", "Ask", "Demander",  "询问" },  // STR_AMS_MODE_ASK
  // Not "Immer an": next to "Nachfragen" that reads as "the question is
  // always on", which is the opposite of what it does. Users asking for a way
  // out of the popup had the mode in front of them and did not recognise it.
  { "Automatisch", "Automatic", "Automatique", "自动" },  // STR_AMS_MODE_ALWAYS
  { "Es wird nichts vorgemerkt. Wiegen und Lagerort verhalten sich genau wie bisher.",
    "Nothing is reserved. Weighing and location behave exactly as before.",
    "Rien n'est réservé. La pesée et le choix de l'emplacement restent inchangés.",
    "不预留料盘。称重与存放位置行为与此前完全一致。" },  // STR_AMS_OFF_DESC
  { "Beim Abnehmen wird gefragt, ob die Spule in den Drucker wandert. Ein Ja sendet das Gewicht und öffnet das Fenster.",
    "When the spool is lifted you are asked whether it goes into the printer. A yes sends the weight and opens the window.",
    "Au retrait, la balance demande si la bobine va dans l'imprimante. Un oui envoie le poids et ouvre la fenêtre d'affectation.",
    "拿起料盘时询问是否放入打印机。选“是”将发送重量并开启分配窗口。" },  // STR_AMS_ASK_DESC
  // The gain first, the price second: this is the mode people come looking
  // for when the popup is in their way, so it has to say so before it warns.
  { "Kein Popup, kein Countdown: jede Wiegung merkt die Spule vor. Der Preis ist, dass auch kurzes Nachwiegen sie vormerkt.",
    "No popup, no countdown: every weighing reserves the spool. The price is that checking a weight reserves it too.",
    "Ni question ni compte à rebours : chaque pesée réserve la bobine. Contrepartie : une pesée de contrôle la réserve aussi.",
    "无弹窗、无倒计时：每次称重均预留料盘。代价是单纯复称也会触发预留。" },  // STR_AMS_ALWAYS_DESC
  { "Fenster", "Window", "Fenêtre", "窗口时长" },  // STR_AMS_WINDOW_LBL
  { "wie lange die Spule vorgemerkt bleibt", "how long the spool stays reserved",
    "durée de réservation de la bobine",
    "料盘预留的持续时间" },  // STR_AMS_WINDOW_HINT
  { "s", "s", "s", "s" },  // STR_AMS_SEC_UNIT
  { "Bei Ablauf", "When it runs out",
    "À l'expiration",
    "超时默认" },  // STR_AMS_TIMER_LBL
  { "wenn niemand antwortet", "when nobody answers",
    "si personne ne répond",
    "无人操作时的默认选择" },  // STR_AMS_TIMER_HINT
  { "Ja",   "Yes", "Oui", "是" },  // STR_AMS_TIMER_YES
  { "Nein", "No",  "Non", "否" },  // STR_AMS_TIMER_NO
  { "Spule jetzt ins AMS legen?", "Putting the spool into the AMS?",
    "Mettre la bobine dans l'AMS ?",
    "现在将料盘放入 AMS？" },  // STR_AMS_POPUP_Q
  { "Zuordnung startet in %d s", "Assignment starts in %d s",
    "Affectation dans %d s",
    "%d 秒后开始分配" },  // STR_AMS_POPUP_STARTS_IN
  { "Ohne Zuordnung in %d s", "Without assigning in %d s",
    "Sans affectation dans %d s",
    "%d 秒后取消分配" },  // STR_AMS_POPUP_CLOSES_IN
  { "Ja, zuordnen", "Yes, assign",
    "Oui, affecter",
    "是，分配" },  // STR_AMS_BTN_YES
  { "Der ApiKey darf keine Geräte verwalten",
    "This ApiKey may not manage devices",
    "Cette clé d'API ne peut pas gérer les appareils",
    "此 ApiKey 无设备管理权限" },  // STR_AMS_ERR_FORBIDDEN
  { "Server antwortet nicht (HTTP %d)", "Server not answering (HTTP %d)",
    "Le serveur ne répond pas (HTTP %d)",
    "服务器无响应 (HTTP %d)" },  // STR_AMS_ERR_HTTP
  { "%.0f g sind gespeichert", "%.0f g are saved",
    "%.0f g sont enregistrés",
    "已保存 %.0f g" },  // STR_AMS_POPUP_SAVED
  { "Zuordnung %d s", "Assigning %d s",
    "Affectation %d s",
    "分配中 %d 秒" },  // STR_AMS_WINDOW_RUNNING
  { "Server: Zuordnung aktiv", "Server: assigning active",
    "Serveur : affectation active",
    "服务器：分配已激活" },  // STR_AMS_SRV_ON
  { "Server: aus", "Server: off",
    "Serveur : désactivé",
    "服务器: 关" },  // STR_AMS_SRV_OFF
  { "%.0f g werden dabei gespeichert", "%.0f g will be saved too",
    "%.0f g seront enregistrés au passage",
    "同时保存 %.0f g" },  // STR_AMS_POPUP_WILL_SAVE
  { "Neu aus Tag anlegen", "Create from tag",
    "Créer depuis le tag",
    "从标签新建" },  // STR_NEWTAG_BTN
  { "Spule aus Tag anlegen?", "Create spool from tag?",
    "Créer la bobine depuis le tag ?",
    "从标签新建料盘？" },  // STR_NEWTAG_TITLE
  { "%s %s\nFarbe: %s\nWaagengewicht (netto): %.0f g", "%s %s\nColour: %s\nScale weight (net): %.0f g",
    "%s %s\nCouleur : %s\nPoids sur la balance (net) : %.0f g",
    "%s %s\n颜色: %s\n称重净重: %.0f g" },  // STR_NEWTAG_MSG
  { "Nenngewicht", "Label weight",
    "Poids nominal",
    "标称重量" },  // STR_NEWTAG_LABEL_W
  { "Spule angelegt!", "Spool created!",
    "Bobine créée !",
    "已创建料盘！" },  // STR_NEWTAG_OK
  { "Anlegen fehlgeschlagen", "Could not create spool",
    "Création impossible",
    "创建料盘失败" },  // STR_NEWTAG_FAIL

  { "Tag-Feld", "Tag field", "Champ du tag", "标签字段" },  // STR_TAG_FIELD
  { "Jedes Projekt legt die Tag-UID in ein anderes Extra-Feld, weil Spoolman "
    "lange keines dafür hatte. Seit Version 0.27 hat Spoolman ein eigenes "
    "Tag-Modell.\n\n"
    "Hier wird bestimmt, wohin die Waage schreibt. Kann der Server das native "
    "Modell, wählt sie es beim ersten Scan von selbst - eine Auswahl, die du "
    "selbst getroffen hast, bleibt stehen.\n\n"
    "Gelesen wird immer aus allen Quellen, damit beim Umstellen keine Spule "
    "unsichtbar wird. Beim nächsten Verknüpfen wandert eine anderswo gefundene "
    "UID in die gewählte Quelle.\n\n"
    "Fehlt das gewählte Extra-Feld auf dem Server, legt die Waage es beim "
    "ersten Schreiben selbst an. Für Spoolman NFC ist kein Feld nötig.",
    "Every project puts the tag UID in a different extra field, because "
    "Spoolman had none for it for a long time. Since version 0.27 Spoolman has "
    "a tag model of its own.\n\n"
    "This is where you say what the scale writes to. On a server that has the "
    "native model it picks that by itself on the first scan; a choice you made "
    "yourself is left alone.\n\n"
    "Every source is always read, so nothing goes missing when you switch. On "
    "the next link a UID found elsewhere moves into the selected source.\n\n"
    "If the selected extra field is missing on the server, the scale creates "
    "it on the first write. Spoolman NFC needs no field.",
    "Chaque logiciel range l'identifiant (UID) du tag dans son propre champ supplémentaire, car Spoolman n'en a longtemps proposé aucun. Depuis la version 0.27, Spoolman a sa propre gestion des tags.\n\nCe réglage indique où la balance écrit. Si le serveur gère les tags nativement, elle choisit cette gestion d'elle-même au premier tag lu, sauf si vous avez déjà fait votre choix.\n\nToutes les sources sont toujours lues, pour qu'aucune bobine ne devienne introuvable si vous changez de source. Quand vous liez à nouveau une bobine, son UID trouvé ailleurs passe dans la source choisie.\n\nSi le champ choisi manque sur le serveur, la balance le crée à la première écriture. Spoolman NFC n'a besoin d'aucun champ.",
    "由于 Spoolman 长期没有内置标签字段，各项目会将标签 UID 存入不同的扩展字段。自 0.27 版本起，Spoolman 已拥有原生的标签模型。\n\n在此设置秤写入的目标字段。若服务器支持原生模型，首次扫描时将自动选用；您手动指定的选项则保持不变。\n\n读取时始终会检索所有来源，切换字段不会导致料盘丢失。下次绑定时，在其他来源找到的 UID 将自动迁移至当前选定的字段。\n\n若服务器上缺少所选的扩展字段，秤会在首次写入时自动创建。使用 Spoolman NFC 则无需任何扩展字段。" },  // STR_TAG_FIELD_INFO

  { "Spoolman NFC (nativ)", "Spoolman NFC (native)", "Spoolman NFC (natif)",
    "Spoolman NFC（原生）" },  // STR_TF_NATIVE
  { "Vom Server unterstützt", "Supported by the server", "Pris en charge par le serveur",
    "服务器已支持" },  // STR_TF_NATIVE_SUB
  { "Erst ab Spoolman v0.27", "Spoolman v0.27 and later", "À partir de Spoolman v0.27",
    "需 Spoolman v0.27 及以上" },  // STR_TF_NATIVE_NA
  { "Spoolman hat seit Version 0.27 ein eigenes Tag-Modell, statt einer UID in "
    "einem Extra-Feld. Diese Zeile ist wählbar, sobald der Server es kann.\n\n"
    "Was es besser macht: eine Spule kann mehrere Tags tragen, ohne Liste in "
    "einem Textfeld. Ein Scan ist eine einzige Anfrage, die die Spule gleich "
    "mitliefert, statt Suche plus Nachprüfung. Und ein Tag, der schon an einer "
    "anderen Spule hängt, wird als solcher gemeldet statt still "
    "überschrieben.\n\n"
    "Die Extra-Felder bleiben trotzdem wählbar: SpoolLink, SpoolSense und "
    "FilaMan schreiben weiter ihre eigenen, und wer eines davon parallel "
    "betreibt, braucht es.",
    "Since version 0.27 Spoolman has a tag model of its own, instead of a UID "
    "in an extra field. This entry is selectable once the server has it.\n\n"
    "What it does better: a spool can hold several tags with no list squeezed "
    "into a text field. A scan is one request that returns the spool with it, "
    "rather than a search plus a verification pass. And a tag that already "
    "belongs to another spool is reported as such instead of being silently "
    "overwritten.\n\n"
    "The extra fields stay selectable regardless: SpoolLink, SpoolSense and "
    "FilaMan keep writing their own, and anyone running one of them alongside "
    "still needs it.",
    "Depuis la version 0.27, Spoolman gère les tags lui-même, au lieu d'un UID dans un champ supplémentaire. Cette ligne est sélectionnable dès que le serveur le permet.\n\nAvantages : une bobine peut porter plusieurs tags, sans liste tassée dans un champ texte. Lire un tag ne demande qu'une requête, qui renvoie directement la bobine, au lieu d'une recherche puis d'une vérification. Et un tag déjà lié à une autre bobine est signalé, au lieu d'être écrasé sans prévenir.\n\nLes champs supplémentaires restent malgré tout sélectionnables : SpoolLink, SpoolSense et FilaMan continuent d'écrire dans les leurs, et si vous utilisez l'un d'eux en parallèle, il vous faut son champ.",
    "自 0.27 版本起，Spoolman 拥有了独立的原生标签模型，无需再将 UID 存入扩展字段。服务器支持该特性后即可选择此项。\n\n优势在于：单个料盘可绑定多个标签，无需将列表塞进文本字段；单次扫描请求即可直接返回料盘信息，无需先搜索再验证；若标签已绑定至其他料盘，系统会明确提示，而非静默覆盖。\n\n其余扩展字段仍保留可选：SpoolLink、SpoolSense 和 FilaMan 仍写入各自的字段，若您同时运行这些工具，仍需选择对应字段。" },  // STR_TF_NATIVE_INFO
  { "extra.tag", "extra.tag", "extra.tag",
    "extra.tag" },  // STR_TF_TAG
  { "Diese Waage, OpenSpoolman", "This scale, OpenSpoolman", "Cette balance, OpenSpoolman",
    "本设备及 OpenSpoolman 默认" },  // STR_TF_TAG_SUB
  { "Das Feld, das diese Waage seit jeher benutzt, und das auch OpenSpoolman "
    "und spoolnymous schreiben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Die Waage legt die UID so ab, wie "
    "sie sie liest - als reines Hex ohne Trenner, bei Bambu-Tags die tray_uuid. "
    "OpenSpoolman legt dort eine eigene UUID ab, die Feldbelegung ist also "
    "gleich, der Inhalt nicht zwingend.\n\n"
    "Die richtige Wahl, wenn nichts dagegen spricht.",
    "The field this scale has always used, and the one OpenSpoolman and "
    "spoolnymous write as well.\n\n"
    "One value per spool, no list format. The scale stores the UID the way it "
    "reads it, as plain hex without separators, and the tray_uuid for Bambu tags. OpenSpoolman "
    "puts a UUID of its own in there, so the field matches but the contents "
    "need not.\n\n"
    "The right choice unless something speaks against it.",
    "Le champ que cette balance utilise depuis toujours, et où écrivent aussi OpenSpoolman et spoolnymous.\n\nUne seule valeur par bobine, pas de liste. La balance y écrit l'UID en hexadécimal majuscule sans séparateur (la tray_uuid pour un tag Bambu). OpenSpoolman y range son propre identifiant (UUID) : même champ, mais pas forcément même contenu.\n\nLe bon choix, sauf raison contraire.",
    "本设备一直使用的字段，OpenSpoolman 和 spoolnymous 也写入此字段。\n\n每个料盘仅存单个值，非列表格式。秤会按读取原样存储 UID（无分隔符的纯十六进制字符串），Bambu 标签则存储 tray_uuid。OpenSpoolman 会在此写入其自有的 UUID，因此字段名相同但内容未必一致。\n\n若无特殊兼容需求，推荐首选此项。" },  // STR_TF_TAG_INFO

  { "extra.nfc_id", "extra.nfc_id", "extra.nfc_id", "extra.nfc_id" },  // STR_TF_NFCID
  { "FilaMan, nfc2klipper, SpoolSense", "FilaMan, nfc2klipper, SpoolSense",
    "FilaMan, nfc2klipper, SpoolSense",
    "FilaMan, nfc2klipper, SpoolSense" },  // STR_TF_NFCID_SUB
  { "Das Feld, auf das sich FilaMan, nfc2klipper und SpoolSense geeinigt "
    "haben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Erwartet wird reines Hex in "
    "Großbuchstaben ohne Trenner - die Waage schreibt hier also "
    "04A1B2C3D4E5F6 statt 04:A1:B2:C3:D4:E5:F6, sonst finden die anderen "
    "Programme die UID nicht.\n\n"
    "Sinnvoll, wenn eines davon parallel auf dieselbe Spoolman-Datenbank "
    "zugreift.",
    "The field FilaMan, nfc2klipper and SpoolSense settled on.\n\n"
    "One value per spool, no list format. It expects plain uppercase hex "
    "without separators, so the scale writes 04A1B2C3D4E5F6 rather than "
    "04:A1:B2:C3:D4:E5:F6 - otherwise the other tools will not find the "
    "UID.\n\n"
    "Useful when one of them works on the same Spoolman database.",
    "Le champ sur lequel FilaMan, nfc2klipper et SpoolSense se sont accordés.\n\nUne seule valeur par bobine, pas de liste. Ces logiciels attendent de l'hexadécimal majuscule sans séparateur : la balance écrit donc 04A1B2C3D4E5F6 et non 04:A1:B2:C3:D4:E5:F6, sinon ils ne trouveraient pas l'UID.\n\nUtile si l'un d'eux accède en parallèle à la même base Spoolman.",
    "FilaMan、nfc2klipper 和 SpoolSense 共同约定的字段。\n\n每个料盘仅存单个值，非列表格式。它要求使用无分隔符的大写纯十六进制字符串，因此秤会写入 04A1B2C3D4E5F6 而非 04:A1:B2:C3:D4:E5:F6，否则其他工具将无法识别该 UID。\n\n当上述工具与本设备共用同一 Spoolman 数据库时适用。" },  // STR_TF_NFCID_INFO

  { "extra.card_uids", "extra.card_uids", "extra.card_uids",
    "extra.card_uids" },  // STR_TF_CARDUIDS
  { "SpoolLink, Snapmaker U1", "SpoolLink, Snapmaker U1", "SpoolLink, Snapmaker U1",
    "SpoolLink, Snapmaker U1" },  // STR_TF_CARDUIDS_SUB
  { "Das Feld, das SpoolLink in der Snapmaker-Firmware und Spool Studio "
    "benutzen.\n\n"
    "Das einzige Extra-Feld, das eine Liste aufnimmt: mehrere UIDs, "
    "kommagetrennt, reines Hex in Großbuchstaben. Beim Snapmaker U1 ist das "
    "die Regel, weil eine Spule je ein Tag pro Flansch trägt und auf beide "
    "Seiten des Druckers passen muss.\n\n"
    "Von den Extra-Feldern lässt nur dieses die Option \"Mehrere Tags "
    "verknüpfen\" zu. Spoolman NFC kann das ebenfalls und braucht keinen "
    "Schalter dafür, weil mehrere Tags dort der Normalfall sind statt eines "
    "Formats in einem Textfeld. Wer die Wahl hat, nimmt Spoolman NFC - dieses "
    "Feld ist die richtige Wahl, wenn SpoolLink daneben laufen soll.",
    "The field SpoolLink in the Snapmaker firmware and Spool Studio use.\n\n"
    "The only extra field that holds a list: several UIDs, comma separated, "
    "plain uppercase hex. On the Snapmaker U1 that is the rule, because a "
    "spool carries one tag per flange so it fits either side of the "
    "printer.\n\n"
    "Of the extra fields only this one allows \"Link multiple tags\". Spoolman "
    "NFC can do it too and needs no switch, because several tags are the "
    "normal case there rather than a format squeezed into a text field. Given "
    "the choice, take Spoolman NFC - this field is the right one when "
    "SpoolLink is to run alongside.",
    "Le champ qu'utilisent SpoolLink (firmware Snapmaker) et Spool Studio.\n\nLe seul champ supplémentaire qui accepte une liste : plusieurs UID séparés par des virgules, en hexadécimal majuscule. C'est la règle sur le Snapmaker U1 : une bobine porte un tag par flasque, pour se monter d'un côté comme de l'autre de l'imprimante.\n\nParmi les champs supplémentaires, seul celui-ci permet l'option « Lier plusieurs tags ». Spoolman NFC le permet aussi, sans cette option, car plusieurs tags y sont la norme et non un format tassé dans un champ texte. Si vous avez le choix, prenez Spoolman NFC ; ce champ convient si SpoolLink doit tourner en parallèle.",
    "Snapmaker 固件中的 SpoolLink 与 Spool Studio 所使用的字段。\n\n这是唯一支持列表的扩展字段：可存放多个以逗号分隔的大写纯十六进制 UID。这在 Snapmaker U1 上是标准做法，因为料盘两侧料盘壁各贴有一个标签，以便装入打印机任意一侧。\n\n在所有扩展字段中，仅此项允许启用\"绑定多个标签\"。Spoolman NFC 原生支持多标签且无需额外开关，因为多标签在其中属于常规用法，而非硬塞进文本字段的格式。若条件允许，优先选用 Spoolman NFC；仅当需与 SpoolLink 并行使用时才选此字段。" },  // STR_TF_CARDUIDS_INFO

  { "Trocknungsdatum", "Drying date", "Date de séchage", "烘干日期" },  // STR_EF_LAST_DRIED
  { "Wann die Spule zuletzt getrocknet wurde. Spoolman hat dafür kein eigenes "
    "Feld, deshalb schreibt die Waage es nach extra.last_dried.\n\n"
    "Fehlt das Feld, legt die Waage es beim ersten Speichern einer Trocknung "
    "selbst an.",
    "When the spool was last dried. Spoolman has no field of its own for it, "
    "so the scale writes it to extra.last_dried.\n\n"
    "If the field is missing, the scale creates it the first time a drying is "
    "saved.",
    "Date du dernier séchage de la bobine. Spoolman n'a pas de champ pour cela : la balance l'écrit donc dans extra.last_dried.\n\nS'il manque, la balance le crée au premier séchage enregistré.",
    "记录料盘上次烘干的时间。由于 Spoolman 没有内置该字段，秤会将其写入 extra.last_dried。\n\n若服务器上缺少此字段，秤会在首次保存烘干记录时自动创建。" },  // STR_EF_LAST_DRIED_INFO

  { "vorhanden",            "present",               "présent",           "已存在" },  // STR_EF_PRESENT
  { "fehlt auf dem Server", "missing on the server", "absent du serveur", "服务器中缺失" },  // STR_EF_MISSING
  { "Feld auf dem Server anlegen", "Create the field on the server",
    "Créer le champ sur le serveur",
    "在服务器上创建此字段" },  // STR_EF_CREATE_ROW
  { "Lade Spulen ...", "Loading spools ...",
    "Chargement des bobines ...",
    "正在加载料盘..." },  // STR_LOADING_SPOOLS
  { "%d Spulen, sortiere ...", "%d spools, sorting ...",
    "%d bobines, tri en cours ...",
    "%d 个料盘，排序中..." },  // STR_LOADING_FILTER

  // ── Web interface ─────────────────────────────────────
  { "Status",
    "Status",
    "État",
    "状态" },  // STR_W_NAV_STATUS
  { "Backend",
    "Backend",
    "Backend",
    "后端" },  // STR_W_NAV_BACKEND
  { "Trocknung",
    "Drying",
    "Séchage",
    "烘干" },  // STR_W_NAV_DRYING
  { "Tags",
    "Tags",
    "Tags",
    "标签" },  // STR_W_NAV_TAGS
  { "Einstellungen",
    "Settings",
    "Réglages",
    "设置" },  // STR_W_NAV_SETTINGS
  { "Logs",
    "Logs",
    "Journaux",
    "日志" },  // STR_W_NAV_LOGS
  { "Firmware",
    "Firmware",
    "Firmware",
    "固件" },  // STR_W_NAV_FIRMWARE
  { "Unabhängig von Spoolman, FilaMan und BamBuddy - Open-Source-Projekt",
    "Not affiliated with Spoolman, FilaMan or BamBuddy - Open Source Project",
    "Sans lien avec Spoolman, FilaMan ou BamBuddy - projet open source",
    "与 Spoolman、FilaMan 或 BamBuddy 无关 - 开源项目" },  // STR_W_DISCLAIMER
  { "Speichern",
    "Save",
    "Enregistrer",
    "保存" },  // STR_W_SAVE
  { "Gespeichert",
    "Saved",
    "Enregistré",
    "已保存" },  // STR_W_SAVED
  { "Fehler",
    "Error",
    "Erreur",
    "错误" },  // STR_W_ERROR
  { "Auf Standard zurück",
    "Reset to defaults",
    "Rétablir les valeurs par défaut",
    "恢复默认设置" },  // STR_W_DEFAULTS
  { "%s ist ausgeschaltet",
    "%s is switched off",
    "%s est désactivé",
    "%s 已关闭" },  // STR_W_OFF_TITLE
  { "Dieser Bereich ist am Gerät abgeschaltet und wird deshalb nicht ausgeliefert.",
    "This section is disabled on the device, so it is not being served.",
    "Cette section est désactivée sur l'appareil, elle n'est donc pas servie.",
    "此功能模块已在设备上禁用，因此当前无法访问。" },  // STR_W_OFF_BODY
  { "Hier einschalten:",
    "Turn it on here:",
    "Activez-la ici :",
    "请前往以下路径开启：" },  // STR_W_OFF_WHERE
  { "Einstellungen &rsaquo; System &rsaquo; Weboberfläche",
    "Settings &rsaquo; System &rsaquo; Web interface",
    "Réglages &rsaquo; Système &rsaquo; Interface web",
    "设置 &rsaquo; 系统 &rsaquo; Web 界面" },  // STR_W_OFF_PATH
  { "Danach diese Seite neu laden.",
    "Then reload this page.",
    "Rechargez ensuite cette page.",
    "随后请刷新此页面。" },  // STR_W_OFF_RELOAD
  { "Zurück zum Status",
    "Back to status",
    "Retour à l'état",
    "返回状态页" },  // STR_W_BACK_STATUS
  { "Netzwerk",
    "Network",
    "Réseau",
    "网络" },  // STR_W_C_NETWORK
  { "Hardware",
    "Hardware",
    "Matériel",
    "硬件" },  // STR_W_C_HARDWARE
  { "Bestandsverwaltung",
    "Inventory",
    "Gestion des stocks",
    "库存管理" },  // STR_W_C_INVENTORY
  { "Zugriff",
    "Access",
    "Accès",
    "访问控制" },  // STR_W_C_ACCESS
  { "Gerät",
    "Device",
    "Appareil",
    "设备" },  // STR_W_C_DEVICE
  { "WLAN",
    "WiFi",
    "WiFi",
    "WiFi" },  // STR_W_R_WIFI
  { "Adresse",
    "Address",
    "Adresse",
    "IP 地址" },  // STR_W_R_ADDRESS
  { "Name",
    "Name",
    "Nom",
    "主机名" },  // STR_W_R_NAME
  { "Gateway",
    "Gateway",
    "Passerelle",
    "网关" },  // STR_W_R_GATEWAY
  { "Waage",
    "Scale",
    "Balance",
    "称重模块" },  // STR_W_R_SCALE
  { "NFC-Leser",
    "NFC reader",
    "Lecteur NFC",
    "NFC 读卡器" },  // STR_W_R_NFC
  { "SD-Karte",
    "SD card",
    "Carte SD",
    "SD 卡" },  // STR_W_R_SD
  { "Laufzeit",
    "Uptime",
    "Durée de marche",
    "运行时间" },  // STR_W_R_UPTIME
  { "Backend",
    "Backend",
    "Backend",
    "后端服务" },  // STR_W_R_BACKEND
  { "Erreichbar",
    "Reachable",
    "Joignable",
    "可访问" },  // STR_W_R_REACHABLE
  { "Tags gescannt",
    "Tags scanned",
    "Tags scannés",
    "已扫描标签" },  // STR_W_R_SCANS
  { "bereit",
    "ready",
    "en service",
    "就绪" },  // STR_W_S_READY
  { "fehlt",
    "missing",
    "introuvable",
    "未检测到" },  // STR_W_S_MISSING
  { "an",
    "on",
    "oui",
    "开启" },  // STR_W_S_ON
  { "aus",
    "off",
    "non",
    "关闭" },  // STR_W_S_OFF
  { "ja",
    "yes",
    "oui",
    "是" },  // STR_W_S_YES
  { "nein",
    "no",
    "non",
    "否" },  // STR_W_S_NO
  { "nicht verbunden",
    "not connected",
    "hors ligne",
    "未连接" },  // STR_W_S_NOWIFI
  { "Was ausgeschaltet ist, wird nicht ausgeliefert - auch die Endpunkte dahinter nicht. Umschalten am Gerät unter",
    "A section that is off is not served at all, and neither are the endpoints behind it. Switch it on the device under",
    "Une section désactivée est totalement inaccessible, y compris par ses adresses d'API. Se règle sur l'appareil, dans",
    "已关闭的模块及其对应的接口均不会提供服务。可在设备端进入以下路径开启：" },  // STR_W_ACCESS_NOTE
  { "Neu starten",
    "Restart",
    "Redémarrer",
    "重启" },  // STR_W_RESTART
  { "Alle Einstellungen liegen im NVS, ein Neustart verliert nichts.",
    "Settings are kept in NVS, so a restart loses nothing.",
    "Tous les réglages restent en mémoire permanente : un redémarrage n'en perd aucun.",
    "所有设置均保存在 NVS 中，重启不会丢失任何配置。" },  // STR_W_RESTART_NOTE
  { "Gerät jetzt neu starten?",
    "Restart the device now?",
    "Redémarrer l'appareil maintenant ?",
    "立即重启设备？" },  // STR_W_RESTART_ASK
  { "Startet neu",
    "Restarting",
    "Redémarrage",
    "正在重启" },  // STR_W_RESTARTING
  { "warte auf das Gerät",
    "waiting for the device",
    "attente de l'appareil",
    "正在等待设备响应" },  // STR_W_RESTART_WAIT
  { " (SD-Karte steckt, der Start dauert rund 20 s länger)",
    " (SD card fitted, boot takes about 20s longer)",
    " (carte SD présente, le démarrage prend environ 20 s de plus)",
    " （已插入 SD 卡，启动时间约延长 20 秒）" },  // STR_W_RESTART_SD
  { "immer noch am Warten",
    "still waiting",
    "toujours en attente",
    "仍在等待响应" },  // STR_W_RESTART_LONG
  { "Das Gerät hat nicht geantwortet. Vielleicht ist es nicht mehr im Netz -",
    "The device has not answered. It may be off the network -",
    "L'appareil n'a pas répondu. Il n'est peut-être plus sur le réseau -",
    "设备未响应，可能已断开网络连接 -" },  // STR_W_RESTART_GONE
  { "neu laden",
    "reload",
    "recharger",
    "刷新" },  // STR_W_RELOAD
  { "Adresse",
    "Address",
    "Adresse",
    "地址" },  // STR_W_C_BACKEND_ADDR
  { "Adresse des Backends",
    "Backend address",
    "Adresse du backend",
    "后端地址" },  // STR_W_HOST_LABEL
  { "Hostname oder IP, bei Bedarf mit Port. Ein Name funktioniert auch hinter einem Reverse Proxy, wo die IP allein nicht ans Ziel führt.",
    "Host name or IP, with a port when one is needed. A name also works behind a reverse proxy, where the IP alone does not reach the target.",
    "Nom d'hôte ou adresse IP, avec le port si besoin. Un nom fonctionne aussi derrière un proxy inverse, où l'adresse IP seule ne mène pas au serveur visé.",
    "输入主机名或 IP，如需端口请一并填写。在反向代理环境下，主机名同样适用（此时仅靠 IP 无法直接访问目标）。" },  // STR_W_HOST_HINT
  { "Ohne Port geht es auf 80. Üblich sind Spoolman 7912, FilaMan 8083, BamBuddy 8000.",
    "Without a port this goes to 80. The usual ones are Spoolman 7912, FilaMan 8083, BamBuddy 8000.",
    "Sans port indiqué, le port 80 est utilisé. Ports habituels : Spoolman 7912, FilaMan 8083, BamBuddy 8000.",
    "未指定端口时默认使用 80。常用端口：Spoolman 为 7912，FilaMan 为 8083，BamBuddy 为 8000。" },  // STR_W_HOST_PORTHINT
  { "Die Adresse darf nicht leer sein.",
    "The address cannot be empty.",
    "L'adresse ne peut pas être vide.",
    "地址不能为空。" },  // STR_W_HOST_EMPTY
  { "https wird noch nicht unterstützt. Die Waage spricht nur http.",
    "https is not supported yet. The scale speaks plain http only.",
    "https n'est pas encore pris en charge. La balance ne parle que http.",
    "暂不支持 https，称重台仅支持纯 http 协议。" },  // STR_W_HOST_HTTPS
  { "Verbinde ...",
    "Connecting ...",
    "Connexion ...",
    "正在连接..." },  // STR_W_HOST_TESTING
  { "Erreichbar",
    "Reachable",
    "Joignable",
    "可访问" },  // STR_W_HOST_OK
  { "Nicht erreichbar",
    "Not reachable",
    "Injoignable",
    "无法访问" },  // STR_W_HOST_FAIL
  { "Zugangsdaten",
    "Credentials",
    "Identifiants",
    "凭据设置" },  // STR_W_C_CREDS
  { "API-Key",
    "API key",
    "Clé d'API",
    "API 密钥" },  // STR_W_APIKEY
  { "Gerätecode",
    "Device code",
    "Code d'appareil",
    "设备码" },  // STR_W_DEVICE_CODE
  { "Registrieren",
    "Register",
    "Associer l'appareil",
    "注册" },  // STR_W_REGISTER
  { "hinterlegt",
    "set",
    "en mémoire",
    "已设置" },  // STR_W_SET
  { "fehlt",
    "missing",
    "à définir",
    "未设置" },  // STR_W_UNSET
  { "Spoolman braucht keine Zugangsdaten.",
    "Spoolman needs no credentials.",
    "Spoolman n'a besoin d'aucun identifiant.",
    "Spoolman 无需配置凭据。" },  // STR_W_NO_CREDS
  { "Schwellwerte je Material",
    "Thresholds per material",
    "Seuils par matériau",
    "各材质烘干阈值" },  // STR_W_C_DRYING
  { "Material",
    "Material",
    "Matériau",
    "材质" },  // STR_W_DRY_MATERIAL
  { "Gelb ab",
    "Amber after",
    "Jaune dès",
    "黄色预警（天后）" },  // STR_W_DRY_YELLOW
  { "Rot ab",
    "Red after",
    "Rouge dès",
    "红色预警（天后）" },  // STR_W_DRY_RED
  { "Lagerung",
    "Storage",
    "Stockage",
    "存放方式" },  // STR_W_DRY_STORAGE
  { "trocken",
    "sealed",
    "sous vide",
    "密封保存" },  // STR_W_DRY_SEALED
  { "Tage",
    "days",
    "jours",
    "天" },  // STR_W_DRY_DAYS
  { "Faktor für trockene Lagerung",
    "Multiplier for sealed storage",
    "Facteur pour un stockage sous vide",
    "密封保存倍率" },  // STR_W_DRY_MULT
  { "Luftdicht gelagert hält Filament länger. Die Schwellwerte oben werden für diese Materialien mit dem Faktor multipliziert.",
    "Filament stored airtight lasts longer. The thresholds above are multiplied by this factor for those materials.",
    "Stocké à l'abri de l'air, le filament se conserve plus longtemps. Pour les matériaux marqués « sous vide », les seuils ci-dessus sont multipliés par ce facteur.",
    "密封保存的耗材防潮时间更长，此类材质的上述阈值将乘以该倍率。" },  // STR_W_DRY_MULT_HINT
  { "Gerätename",
    "Device name",
    "Nom de l'appareil",
    "设备名称" },  // STR_W_C_DEVNAME
  { "Name oder ganze Adresse, zum Beispiel scale.home.arpa. Der Teil vor dem ersten Punkt ist auch der Name, den der Router zeigt.",
    "A name, or a whole address such as scale.home.arpa. The part before the first dot is also the name your router shows.",
    "Un nom, ou une adresse complète comme scale.home.arpa. La partie avant le premier point est aussi le nom que votre routeur affiche.",
    "可输入名称或完整域名（如 scale.home.arpa），第一个点号前的部分也将显示在路由器中。" },  // STR_W_DEVNAME_HINT
  { "Buchstaben, Ziffern und Bindestriche, durch Punkte getrennt. Kein Bindestrich am Anfang oder Ende, keine Leerzeichen, kein leerer Teil zwischen zwei Punkten.",
    "Letters, digits and hyphens, separated by dots. No hyphen at the start or end, no spaces, no empty part between two dots.",
    "Lettres, chiffres et traits d'union, séparés par des points. Pas de trait d'union au début ni à la fin, pas d'espace, aucune partie vide entre deux points.",
    "仅支持字母、数字和连字符，以点号分隔。首尾不能为连字符，不能包含空格或连续点号。" },  // STR_W_DEVNAME_BAD
  { "Jetzt erreichbar unter %s - beim Router nach dem nächsten Verbinden.",
    "Reachable now at %s - the router shows it after the next connection.",
    "Joignable maintenant à %s - le routeur l'affiche après la prochaine connexion.",
    "现已可通过 %s 访问，路由器将在下次重新连接后更新显示名称。" },  // STR_W_DEVNAME_NOW
  { "Listenlimits",
    "List limits",
    "Limites de liste",
    "列表数量限制" },  // STR_W_C_LIMITS
  { "Spulenliste",
    "Spool list",
    "Liste des bobines",
    "料盘列表" },  // STR_W_LIMIT_SPOOLS
  { "Standortliste",
    "Location list",
    "Liste des emplacements",
    "存放位置列表" },  // STR_W_LIMIT_LOCS
  { "Wie viele Einträge die Auswahl am Gerät zeigt.",
    "How many entries the picker on the device shows.",
    "Nombre maximal d'entrées affichées dans la liste de l'appareil.",
    "设置设备屏幕上选择器显示的最大条目数。" },  // STR_W_LIMIT_HINT
  { "Zu viele Einträge lassen die Anzeige einfrieren - ein Neustart erfolgt nicht von selbst.",
    "Too many entries freeze the display - it does not reboot by itself.",
    "Trop d'entrées figent l'affichage - et l'appareil ne redémarre pas de lui-même.",
    "条目过多会导致屏幕卡死，且设备不会自动重启。" },  // STR_W_LIMIT_WARN
  { "Anzeige",
    "Display",
    "Affichage",
    "显示设置" },  // STR_W_C_DISPLAY
  { "Helligkeitsanhebung",
    "Brightness lift",
    "Renfort de luminosité",
    "亮度增益" },  // STR_W_GAIN
  { "100 ist aus. Die Hintergrundbeleuchtung ist bei 255 schon am Anschlag, das hier ist der verbleibende Hebel auf ein dunkles Panel.",
    "100 is off. The backlight is already at its ceiling at 255, so this is the only remaining lever on a dim panel.",
    "À 100, aucun renfort. Le rétroéclairage plafonne déjà à 255 : ce renfort reste le seul moyen d'éclaircir un écran trop sombre.",
    "100 为关闭。背光在 255 时已达硬件上限，这是在较暗屏幕上进一步提亮的唯一选项。" },  // STR_W_GAIN_HINT
  { "Tag beschreiben",
    "Write a tag",
    "Écrire un tag",
    "写入标签" },  // STR_W_C_WRITETAG
  { "Spule",
    "Spool",
    "Bobine",
    "料盘" },  // STR_W_TAG_SPOOL
  { "-- Spule wählen --",
    "-- pick a spool --",
    "-- choisir une bobine --",
    "-- 选择料盘 --" },  // STR_W_TAG_PICK
  { "Auf dem Tag",
    "On the tag",
    "Sur le tag",
    "标签当前内容" },  // STR_W_TAG_ONTAG
  { "Würde geschrieben",
    "Will be written",
    "Sera écrit",
    "待写入内容" },  // STR_W_TAG_WILLBE
  { "Kein Tag auf dem Leser.",
    "No tag on the reader.",
    "Aucun tag sur le lecteur.",
    "读卡器上未检测到标签。" },  // STR_W_TAG_NOTAG
  { "Tag auf dem Leser:",
    "Tag on the reader:",
    "Tag sur le lecteur :",
    "读卡器上的标签：" },  // STR_W_TAG_ONREADER
  { "Erst eine Spule wählen.",
    "Pick a spool first.",
    "Choisissez d'abord une bobine.",
    "请先选择一个料盘。" },  // STR_W_TAG_PICKFIRST
  { "Leerer Tag",
    "Blank tag",
    "Tag vierge",
    "空白标签" },  // STR_W_TAG_BLANK
  { "Daten, die diese Firmware nicht lesen kann",
    "Data this firmware cannot read",
    "Données que ce firmware ne sait pas lire",
    "当前固件无法读取的数据" },  // STR_W_TAG_UNKNOWN
  { "Tag beschreiben",
    "Write tag",
    "Écrire le tag",
    "写入标签" },  // STR_W_TAG_WRITE
  { "Tag überschreiben",
    "Overwrite tag",
    "Écraser le tag",
    "覆盖标签" },  // STR_W_TAG_OVERWRITE
  { "Tag stimmt bereits überein",
    "Tag already matches",
    "Le tag correspond déjà",
    "标签内容已一致" },  // STR_W_TAG_MATCHES
  { "Tag leeren",
    "Erase tag",
    "Vider le tag",
    "擦除标签" },  // STR_W_TAG_ERASE
  { "Alles auf diesem Tag löschen?",
    "Erase everything on this tag?",
    "Effacer tout ce qui est sur ce tag ?",
    "确定擦除此标签上的全部数据？" },  // STR_W_TAG_ERASE_ASK
  { "Spule mit diesem Tag verknüpfen",
    "Link the spool to this tag",
    "Lier la bobine à ce tag",
    "将料盘绑定到此标签" },  // STR_W_TAG_LINK
  { "Diese Spule hängt an %s, das damit zum vorherigen Tag wird.",
    "This spool is linked to %s, which becomes its previous tag.",
    "Cette bobine est liée à %s, qui devient son tag précédent.",
    "此料盘已绑定到 %s，重新绑定后原标签将作为历史标签。" },  // STR_W_TAG_RELINK
  { "Eingereiht.",
    "Queued.",
    "En file d'attente.",
    "已加入队列。" },  // STR_W_TAG_QUEUED
  { "Spulenliste nicht verfügbar",
    "Spool list unavailable",
    "Liste indisponible",
    "无法获取料盘列表" },  // STR_W_TAG_NOLIST
  { "SKU",
    "SKU",
    "Référence",
    "SKU" },  // STR_W_TAG_SKU
  { "Düse",
    "Nozzle",
    "Buse",
    "喷嘴" },  // STR_W_TAG_NOZZLE
  { "Bett",
    "Bed",
    "Plateau",
    "热床" },  // STR_W_TAG_BED
  { "Gewicht",
    "Weight",
    "Poids",
    "重量" },  // STR_W_TAG_WEIGHT
  { "Durchmesser",
    "Diameter",
    "Diamètre",
    "线径" },  // STR_W_TAG_DIA
  { "Länge",
    "Length",
    "Longueur",
    "长度" },  // STR_W_TAG_LENGTH
  { "Links steht, was gerade auf dem Tag liegt, rechts, was die gewählte Spule ergäbe. Abweichende Zeilen sind farbig.",
    "On the left what the tag holds right now, on the right what the selected spool would put there. Lines that differ are coloured.",
    "À gauche, ce que le tag contient en ce moment ; à droite, ce que la bobine choisie y mettrait. Les lignes qui diffèrent sont en couleur.",
    "左侧为标签当前数据，右侧为所选料盘将写入的数据，差异行已高亮显示。" },  // STR_W_TAG_COMPARE
  { "SD-Karte",
    "SD card",
    "Carte SD",
    "SD 卡" },  // STR_W_C_LOGS
  { "Ansehen",
    "View",
    "Voir",
    "查看" },  // STR_W_LOG_VIEW
  { "Löschen",
    "Delete",
    "Supprimer",
    "删除" },  // STR_W_LOG_DELETE
  { "Diese Datei löschen?",
    "Delete this file?",
    "Supprimer ce fichier ?",
    "确定删除此文件？" },  // STR_W_LOG_DELETE_ASK
  { "Keine SD-Karte erkannt",
    "No SD card detected",
    "Aucune carte SD détectée",
    "未检测到 SD 卡" },  // STR_W_LOG_NOSD
  { "Eine FAT32-formatierte Karte einlegen, um die Diagnoseprotokolle zu aktivieren.",
    "Insert a FAT32 formatted card to enable diagnostic logging.",
    "Insérez une carte formatée en FAT32 pour activer les journaux de diagnostic.",
    "请插入 FAT32 格式的 SD 卡以启用诊断日志。" },  // STR_W_LOG_NOSD_HINT
  { "Noch keine Protokolle.",
    "No logs yet.",
    "Aucun journal pour l'instant.",
    "暂无日志。" },  // STR_W_LOG_EMPTY
  { "Firmware",
    "Firmware",
    "Firmware",
    "固件" },  // STR_W_C_FIRMWARE
  { "Installiert",
    "Installed",
    "Version installée",
    "已安装版本" },  // STR_W_FW_INSTALLED
  { "Datei hochladen",
    "Upload a file",
    "Envoyer un fichier",
    "上传固件文件" },  // STR_W_FW_FILE
  { "Flashen",
    "Flash",
    "Flasher",
    "刷写" },  // STR_W_FW_FLASH
  { "Das Gerät startet nach dem Schreiben von selbst neu. Strom nicht trennen.",
    "The device restarts by itself once written. Do not cut the power.",
    "Après l'écriture du firmware, l'appareil redémarre de lui-même. Ne coupez pas l'alimentation.",
    "写入完成后设备将自动重启，请勿断电。" },  // STR_W_FW_HINT
  { "Update erfolgreich",
    "Update successful",
    "Mise à jour réussie",
    "更新成功" },  // STR_W_FW_OK
  { "Das Gerät startet neu ...",
    "Device is restarting ...",
    "L'appareil redémarre ...",
    "设备正在重启..." },  // STR_W_FW_RESTARTING
  { "Update fehlgeschlagen",
    "Update failed",
    "Échec de la mise à jour",
    "更新失败" },  // STR_W_FW_FAIL
  { "Bitte erneut versuchen.",
    "Please try again.",
    "Veuillez réessayer.",
    "请重试。" },  // STR_W_FW_RETRY
  { "Update über GitHub",
    "Update from GitHub",
    "Mise à jour par GitHub",
    "从 GitHub 更新" },  // STR_W_C_FW_GITHUB
  { "Kanal",
    "Channel",
    "Canal",
    "更新通道" },  // STR_W_FW_CHANNEL
  { "Release",
    "Release",
    "Version stable",
    "正式版" },  // STR_W_FW_CH_STABLE
  { "Vorabversion",
    "Pre-release",
    "Pré-version",
    "预览版" },  // STR_W_FW_CH_PRE
  { "Neueste",
    "Latest",
    "Dernière version",
    "最新版本" },  // STR_W_FW_LATEST
  { "Nach Updates suchen",
    "Check for updates",
    "Rechercher des mises à jour",
    "检查更新" },  // STR_W_FW_CHECK
  { "Suche ...",
    "Checking ...",
    "Recherche ...",
    "正在检查..." },  // STR_W_FW_CHECKING
  { "Bereits aktuell",
    "Already up to date",
    "Déjà à jour",
    "已是最新版本" },  // STR_W_FW_UPTODATE
  { "Update verfügbar",
    "Update available",
    "Mise à jour disponible",
    "发现新版本" },  // STR_W_FW_AVAIL
  { "Installieren",
    "Install",
    "Installer",
    "安装" },  // STR_W_FW_INSTALL
  { "Wird installiert ...",
    "Installing ...",
    "Installation ...",
    "正在安装..." },  // STR_W_FW_INSTALLING
  { "Kein WLAN",
    "No WiFi connection",
    "Pas de connexion WiFi",
    "无 WiFi 连接" },  // STR_W_FW_NOWIFI
  { "Das Gerät prüft oder schreibt gerade",
    "The device is already checking or writing",
    "L'appareil est déjà en train de chercher ou d'écrire",
    "设备正在检查或写入固件" },  // STR_W_FW_BUSY
  { "Suche fehlgeschlagen",
    "Check failed",
    "Échec de la recherche",
    "检查失败" },  // STR_W_FW_CHECK_FAIL
  { "Der Kanal ist derselbe wie am Gerät. Das Image wird vom Gerät geladen, nicht vom Browser.",
    "The channel is the same setting as on the device. The image is fetched by the device, not by this browser.",
    "Le canal est le même réglage que sur l'appareil. C'est l'appareil qui télécharge le firmware, pas ce navigateur.",
    "更新通道设置与设备端一致。固件镜像由设备直接下载，而非通过此浏览器。" },  // STR_W_FW_GH_HINT
  { "Veröffentlicht",
    "Released",
    "Publiée le",
    "发布时间" },  // STR_W_FW_RELEASED
  { "Installiert am",
    "Installed on",
    "Installée le",
    "安装时间" },  // STR_W_FW_SINCE
  { "Release Notes",
    "Release notes",
    "Notes de version",
    "发行说明" },  // STR_W_FW_NOTES
  { "Was ist neu",
    "What is new",
    "Nouveautés",
    "更新内容" },  // STR_W_FW_WHATSNEW
  { "Nicht als Release veröffentlicht",
    "Not a published release",
    "Version non publiée",
    "非公开发布版本" },  // STR_W_FW_UNPUBLISHED
  { "unbekannt",
    "unknown",
    "inconnue",
    "未知" },  // STR_W_FW_UNKNOWN
  { "Ausblenden",
    "Hide",
    "Masquer",
    "隐藏" },  // STR_W_FW_HIDE
  { "{v} installieren?",
    "Install {v}?",
    "Installer {v} ?",
    "确定安装 {v}？" },  // STR_W_FW_CONFIRM
  { "Das Gerät startet nach dem Download automatisch neu, die Seite lädt sich dann selbst. Strom nicht trennen.",
    "The device restarts by itself when the download finishes, and this page reloads. Do not cut the power.",
    "L'appareil redémarre tout seul à la fin du téléchargement, et cette page se recharge. Ne coupez pas l'alimentation.",
    "下载完成后设备将自动重启，此页面也会随之重新加载，请勿断电。" },  // STR_W_FW_REBOOTS
  { "Ältere Version",
    "Older release",
    "Version plus ancienne",
    "旧版本" },  // STR_W_FW_OLDER
  { "Auf {v} zurückstufen?",
    "Downgrade to {v}?",
    "Revenir à {v} ?",
    "确定降级至 {v}？" },  // STR_W_FW_DOWNGRADE
  { "{v} ist älter als die installierte {i}.",
    "{v} is older than the installed {i}.",
    "{v} est plus ancienne que la version installée {i}.",
    "{v} 低于当前已安装的 {i}。" },  // STR_W_FW_DOWNWARN
  { "Gewicht",
    "Weight",
    "Poids",
    "重量" },  // STR_W_R_WEIGHT
  { "Konnte nicht geladen werden.",
    "Could not be loaded.",
    "Chargement impossible.",
    "无法加载。" },  // STR_W_LOAD_FAIL
  { "Jede Zeile auf der Karte ist ein eigener Schreibzugriff. Läuft alles rund, lässt sich das Protokoll oben abschalten, ohne die Karte zu ziehen. Das Sitzungsprotokoll weiter unten läuft immer weiter.",
    "Every line on the card is a write of its own. When everything runs fine, switch the log off above instead of pulling the card. The session log further down keeps running either way.",
    "Chaque ligne du journal est une écriture distincte sur la carte. Quand tout fonctionne bien, désactivez le journal ci-dessus plutôt que de retirer la carte. Le journal de session, plus bas, continue dans tous les cas.",
    "存储卡上的每行日志都会触发一次独立写入。设备运行正常时，建议在上方关闭日志记录，无需拔出存储卡。下方的会话日志无论如何都会持续运行。" },  // STR_W_LOG_NOTE
  { "Sitzungsprotokoll",
    "Session log",
    "Journal de session",
    "会话日志" },  // STR_W_C_SESSION
  { "Die letzten Zeilen seit dem Start, im Arbeitsspeicher gehalten und beim Neustart weg. Eine SD-Karte braucht es nur, um Protokolle zu behalten.",
    "The last lines since start, held in memory and gone on restart. An SD card is only needed to keep logs, not to have them.",
    "Les dernières lignes du journal depuis le démarrage, gardées en mémoire vive et perdues à chaque redémarrage. Une carte SD n'est nécessaire que pour conserver les journaux.",
    "仅保留自开机以来的最新日志，暂存于内存中，重启后清空。只有需要持久保存日志时才需要 SD 卡。" },  // STR_W_SESSION_NOTE
  { "Noch nichts protokolliert.",
    "Nothing logged yet.",
    "Rien de journalisé pour l'instant.",
    "暂无日志记录。" },  // STR_W_SESSION_EMPTY
  { "Aktualisieren",
    "Refresh",
    "Actualiser",
    "刷新" },  // STR_W_SESSION_REFRESH
  { "Wird geladen...",
    "Loading...",
    "Chargement...",
    "正在加载..." },  // STR_W_SESSION_BUSY
  { "Geholt um",
    "Fetched at",
    "Récupéré à",
    "获取于" },  // STR_W_SESSION_UPDATED
  { "Zeilen",
    "lines",
    "lignes",
    "行" },  // STR_W_SESSION_LINES
  { "Angehalten, zum Weiterlesen auf Aktualisieren tippen",
    "Paused, press refresh to follow again",
    "En pause, touchez Actualiser pour reprendre le suivi",
    "已暂停，点击刷新继续跟踪" },  // STR_W_SESSION_PAUSED
  { "neu",
    "new",
    "nouvelles",
    "新增" },  // STR_W_SESSION_NEW
  { "Text kopieren",
    "Copy text",
    "Copier",
    "复制文本" },  // STR_W_SESSION_COPY
  { "Kopiert",
    "Copied",
    "Copié",
    "已复制" },  // STR_W_SESSION_COPIED
  { "Kopieren nicht möglich, bitte markieren",
    "Cannot copy, please select the text",
    "Copie impossible, sélectionnez le texte",
    "无法复制，请手动选中文本" },  // STR_W_SESSION_COPYFAIL
  { "Einen beschreibbaren NTAG auflegen, Spule wählen, schreiben. Was auf dem Tag steht, wird ersetzt. Tags ab Werk sind meist MIFARE Classic oder gesperrt und lassen sich nur lesen.",
    "Place a writable NTAG on the reader, pick a spool, and write it. Whatever is already on the tag is replaced. Factory tags are usually MIFARE Classic or locked, and can only be read.",
    "Posez un NTAG inscriptible sur le lecteur, choisissez une bobine, puis cliquez sur Écrire le tag. Tout ce que contient déjà le tag est remplacé. Les tags posés en usine sont le plus souvent des MIFARE Classic ou sont verrouillés : ils ne peuvent qu'être lus.",
    "将可写入的 NTAG 标签放在读卡器上，选择料盘后点击写入。标签上的原有数据将被覆盖。原厂标签通常为 MIFARE Classic 或已锁定，仅支持读取。" },  // STR_W_TAG_NOTE
  { "<b>Welcher Tag für welches Format.</b> OpenSpool braucht rund 180 Byte und damit einen <b>NTAG215</b> (496 Byte) oder <b>NTAG216</b> (872 Byte). Auf einen NTAG213 (144 Byte) passt davon nichts, dort geht nur Anycubic ACE, das mit 112 Byte auskommt. Meldet ein Tag keine Größe, rechnet die Waage sicherheitshalber mit den 144 Byte eines NTAG213 - dann den Tag einmal mit einer NFC-App als NDEF formatieren, das trägt die Größe ein.",
    "<b>Which tag for which format.</b> OpenSpool needs about 180 bytes, so it wants an <b>NTAG215</b> (496 bytes) or an <b>NTAG216</b> (872 bytes). None of it fits an NTAG213 (144 bytes), which leaves Anycubic ACE, and that needs only 112. A tag that reports no size at all is treated as the 144 bytes of an NTAG213 to stay safe - format such a tag as NDEF once with any NFC app and it will report its real size.",
    "<b>Quel tag pour quel format.</b> OpenSpool a besoin d'environ 180 octets, donc d'un <b>NTAG215</b> (496 octets) ou d'un <b>NTAG216</b> (872 octets). Un NTAG213 (144 octets) est trop petit pour OpenSpool : seul le format Anycubic ACE, qui se contente de 112 octets, y tient. Si un tag n'indique pas sa taille, la balance suppose par prudence qu'il n'a que 144 octets, comme un NTAG213 - dans ce cas, formatez-le une fois en NDEF avec une application NFC, ce qui y inscrit sa taille.",
    "<b>格式与标签容量说明：</b>OpenSpool 需要约 180 字节，因此需使用 <b>NTAG215</b>（496 字节）或 <b>NTAG216</b>（872 字节）。NTAG213（144 字节）无法容纳，仅适用于仅需 112 字节的 Anycubic ACE。若标签未报告容量，系统为安全起见会按 NTAG213 的 144 字节处理——只需使用任意 NFC 应用将其格式化为 NDEF，即可正确报告实际容量。" },  // STR_W_TAG_SIZES
  { "FilaMan legt beides an verschiedenen Stellen an und zeigt es jeweils nur einmal.<br><b>API-Key:</b> auf das Zahnrad neben dem Benutzernamen klicken, <b>API Keys</b> öffnen und einen Key erstellen. Oben eintragen und speichern.<br><b>Gerätecode:</b> <b>Admin-Bereich &gt; Geräte</b> öffnen und <b>Gerät erstellen</b> klicken. Den sechsstelligen Code oben eintragen und registrieren.<br>Ein Gerät anlegen kann nur ein Admin. Den Key mit demselben Konto erstellen, sonst lehnt FilaMan die AMS-Zuordnung ab.",
    "FilaMan creates the two in different places and shows each only once.<br><b>API key:</b> click the gear icon next to your user name, open <b>API Keys</b> and create a key. Enter it above and save.<br><b>Device code:</b> open <b>Admin Panel &gt; Devices</b> and click <b>Create Device</b>. Enter the six character code above and register.<br>Only an admin can create a device. Create the key with the same account, or FilaMan refuses the AMS assignment.",
    "FilaMan crée la clé et le code à deux endroits différents, et n'affiche chacun qu'une seule fois.<br><b>Clé d'API :</b> cliquez sur l'icône d'engrenage à côté de votre nom d'utilisateur, ouvrez <b>Clés API</b> (API Keys) et créez une clé. Saisissez-la ci-dessus et cliquez sur Enregistrer.<br><b>Code d'appareil :</b> ouvrez <b>Espace admin &gt; Appareils</b> (Admin Panel > Devices) et cliquez sur <b>Créer un appareil</b> (Create Device). Saisissez le code à six caractères ci-dessus, puis cliquez sur Associer l'appareil.<br>Seul un administrateur peut créer un appareil. Créez la clé avec ce même compte, sinon FilaMan refuse l'affectation AMS.",
    "FilaMan 会在两个不同位置生成以下凭证，且各自仅显示一次。<br><b>API 密钥：</b>点击用户名旁的齿轮图标，打开 <b>API Keys</b> 并创建密钥，随后在上方输入并保存。<br><b>设备代码：</b>打开 <b>Admin Panel &gt; Devices</b> 并点击 <b>Create Device</b>，随后在上方输入六位代码并注册。<br>仅管理员可创建设备。请使用同一账号创建密钥，否则 FilaMan 将拒绝 AMS 分配。" },  // STR_W_FM_SETUP
  { "Der Schlüssel steht in BamBuddy unter den Einstellungen. Läuft die Instanz ohne Anmeldung, bleibt das Feld leer.",
    "The key is in BamBuddy under settings. Leave the field empty if the instance runs without authentication.",
    "La clé se trouve dans BamBuddy, dans les réglages. Laissez le champ vide si l'instance tourne sans authentification.",
    "密钥位于 BamBuddy 的设置中。若实例未启用身份验证，请将此栏留空。" },  // STR_W_BB_SETUP
  { "Strom nicht trennen",
    "Do not cut the power",
    "Ne coupez pas l'alimentation",
    "请勿断电" },  // STR_OTA_KEEP_POWER
  { "Kaffee ausgeben",
    "Buy me a coffee",
    "Offrir un café",
    "请我喝杯咖啡" },  // STR_W_KOFI
  { "Adresse ist ein Name",
    "Address is a name",
    "L'adresse est un nom",
    "地址为域名" },  // STR_SP_LOCKED_TITLE
  { "Dieser Ziffernblock kann nur Zahlen. Die Adresse im Browser ändern:",
    "This keypad can only make numbers. Change the address in the browser:",
    "Cet écran ne permet de saisir que des chiffres. Modifiez l'adresse depuis un navigateur :",
    "此键盘仅支持数字输入，请在浏览器中修改地址：" },  // STR_SP_LOCKED_INFO
  { "Weboberfläche aus: Einstellungen > System > Weboberfläche",
    "Web interface off: Settings > System > Web interface",
    "Désactivée : Réglages > Système > Interface web",
    "Web 界面已关闭：设置 > 系统 > Web 界面" },  // STR_SP_WEB_OFF
  { "Adresse leeren",
    "Clear address",
    "Effacer l'adresse",
    "清除地址" },  // STR_SP_CLEAR
  { "Adresse verwerfen? Danach ist das Backend nicht mehr eingerichtet, und am Gerät lässt sich nur eine IP eingeben.",
    "Discard the address? The backend is then no longer set up, and the device itself can only enter an IP.",
    "Effacer l'adresse ? Le backend ne sera plus configuré, et sur l'appareil seule une adresse IP pourra être saisie.",
    "确定清除地址？清除后后端将恢复未配置状态，且设备端仅支持输入 IP。" },  // STR_SP_CLEAR_ASK
  { "Alle löschen",
    "Delete all",
    "Tout supprimer",
    "全部删除" },  // STR_W_LOG_DELETE_ALL
  { "{n} Dateien löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete {n} files? Today's log is started over.",
    "Supprimer {n} fichiers ? Le journal du jour est recommencé.",
    "确定删除 {n} 个文件？今日日志将重新开始记录。" },  // STR_W_LOG_DELETE_ALL_ASK
  { "{n} Dateien",
    "{n} files",
    "{n} fichiers",
    "{n} 个文件" },  // STR_W_LOG_COUNT
  // Its own entry rather than a rule in code: which counts need their own
  // wording is a property of the language, not of the list.
  { "1 Datei",
    "1 file",
    "1 fichier",
    "1 个文件" },  // STR_W_LOG_COUNT_ONE
  { "Eine Datei löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete one file? Today's log is started over.",
    "Supprimer un fichier ? Le journal du jour est recommencé.",
    "确定删除此文件？今日日志将重新开始记录。" },  // STR_W_LOG_DELETE_ALL_ASK_ONE
  { "Zeitzone",
    "Time zone",
    "Fuseau horaire",
    "时区" },  // STR_TZ_TITLE
  { "Gilt für jeden Zeitstempel des Geräts und für die Zählung der Trocknungstage. Kein Neustart nötig.",
    "Applies to every timestamp the device writes and to the drying day count. No restart needed.",
    "S'applique aux dates et heures notées par l'appareil et au décompte des jours depuis le dernier séchage. Sans redémarrage.",
    "应用于设备记录的所有时间戳及烘干天数统计，无需重启。" },  // STR_TZ_HINT
  { "Gilt für jeden Zeitstempel des Geräts und für die Zählung der Trocknungstage. Wirkt sofort, ohne Neustart.",
    "Applies to every timestamp the device writes and to the drying day count. Takes effect at once, no restart.",
    "S'applique aux dates et heures notées par l'appareil et au décompte des jours depuis le dernier séchage. Effet immédiat, sans redémarrage.",
    "应用于设备记录的所有时间戳及烘干天数统计，立即生效，无需重启。" },  // STR_W_TZ_NOTE

  { "Felder",
    "Fields",
    "Champs",
    "字段" },  // STR_FLM_FIELDS
  { "wohin der Tag geschrieben wird",
    "where the tag is written",
    "où le tag est écrit",
    "标签数据的写入位置" },  // STR_FLM_FIELDS_SUB
  { "FilaMan hat ein eigenes Feld für NFC-Tags, und die Waage benutzt es. Daneben führt das Bambu-Lab-Plugin zwei Felder für die RFID-Chips einer Bambu-Spule und merkt sich die Tray-UUID in external_id.\n\nGelesen werden alle vier, immer und ohne Schalter: eine Spule, die der Drucker kennt, soll die Waage auch erkennen. Geschrieben wird nur, was hier eingeschaltet ist.",
    "FilaMan has a field of its own for NFC tags and the scale uses it. Alongside it the Bambu Lab plugin keeps two fields for the RFID chips of a Bambu spool, and remembers the tray uuid in external_id.\n\nAll four are read, always and without a switch: a spool the printer knows is a spool this scale should recognise. Only what is switched on here is written.",
    "FilaMan possède son propre champ pour les tags NFC, et la balance l'utilise. Le module Bambu Lab gère en outre deux champs pour les puces RFID d'une bobine Bambu, et enregistre son identifiant Tray-UUID dans external_id.\n\nCes quatre champs sont lus dans tous les cas : une bobine connue de l'imprimante doit aussi être reconnue par la balance. Seul ce qui est activé ici est écrit.",
    "FilaMan 设有专用的 NFC 标签字段，本秤默认使用该字段。此外，Bambu Lab 插件还维护了两个用于存储 Bambu 料盘 RFID 芯片的字段，并在 external_id 中记录托盘 UUID。\n\n读取时始终读取全部四个字段（无需开关）：只要打印机识别的料盘，本秤就能识别。此处仅控制写入哪些字段。" },  // STR_FLM_FIELDS_INFO

  { "Tag-Feld",
    "Tag field",
    "Champ du tag",
    "标签字段" },  // STR_FLM_TAGFIELD
  { "Anders als bei Spoolman gibt es hier nichts zu wählen, und das ist gut so. rfid_uid ist FilaMans eigenes Feld für genau diesen Zweck, es ist das einzige, das die Server-Suche durchsucht, und das Bambu-Plugin fasst es laut eigener Zusage nie an.\n\nEin Ausweichfeld würde jeden Scan vom Schnellpfad auf den vollen Inventar-Scan werfen: unter 1 kB gegen 176 kB bei 280 Spulen.",
    "Unlike Spoolman there is nothing to choose here, and that is a good thing. rfid_uid is FilaMan's own field for exactly this, it is the only one the server side search covers, and the Bambu plugin never touches it - its own documentation says so.\n\nWriting somewhere else would drop every scan from the fast path to a full inventory load: under 1 kB against 176 kB on a library of 280.",
    "Contrairement à Spoolman, il n'y a rien à choisir ici, et c'est une bonne chose. rfid_uid est le champ prévu par FilaMan pour cet usage : c'est le seul que la recherche du serveur parcourt, et le module Bambu s'engage à ne jamais y toucher.\n\nAvec un autre champ, chaque lecture de tag obligerait à télécharger tout l'inventaire au lieu d'une simple recherche : 176 ko au lieu de moins de 1 ko pour 280 bobines.",
    "与 Spoolman 不同，此处无需选择——这反而是好事。rfid_uid 是 FilaMan 专为此设计的字段，也是服务端搜索唯一覆盖的字段，且 Bambu 插件官方文档明确表示绝不会改动它。\n\n若写入其他字段，每次扫描都会从快速查询退化为全量库存加载（在 280 卷料盘的库中，数据量将从不到 1 kB 暴增至 176 kB）。" },  // STR_FLM_TAGFIELD_INFO

  { "Bambu-Tag-Felder pflegen",
    "Maintain the Bambu tag fields",
    "Mettre à jour les champs Bambu",
    "维护 Bambu 标签字段" },  // STR_FLM_BTAGS
  { "Chip-UID in den ersten freien Slot",
    "chip uid into the first free slot",
    "UID de puce dans le premier champ libre",
    "将芯片 UID 写入首个空闲槽位" },  // STR_FLM_BTAGS_SUB
  { "Eine Bambu-Spule trägt zwei RFID-Chips, einen je Seite. Das Plugin füllt nur den ersten der beiden Felder, mit dem, was der Drucker gemeldet hat; den zweiten hält es für einen weiteren Leser frei.\n\nAn: die Waage trägt die Chip-UID der aufliegenden Seite in den ersten freien der beiden Slots ein. Ein belegter Slot wird nie überschrieben. Legt man beide Seiten auf, sind danach beide gefüllt.\n\nNutzen: die Spule wird auch dann gefunden, wenn sich ihr Tag nicht entschlüsseln lässt und nur seine Chip-UID hergibt.",
    "A Bambu spool carries two RFID chips, one per flange. The plugin fills only the first of the two fields, with what the printer reported, and keeps the second free for another reader.\n\nOn: the scale writes the chip uid of the side on the reader into the first free of the two slots. A slot that holds something is never overwritten. Present both sides and both end up filled.\n\nWhat it buys: the spool is still found when its tag will not decrypt and has nothing but its chip uid to offer.",
    "Une bobine Bambu porte deux puces RFID, une de chaque côté. Le module Bambu ne remplit que le premier des deux champs, avec ce que l'imprimante a signalé, et laisse le second libre pour un autre lecteur.\n\nActivé : la balance inscrit l'identifiant (UID) de la puce posée sur le lecteur dans le premier des deux champs resté vide. Un champ rempli n'est jamais écrasé. Posez un côté puis l'autre : les deux seront remplis.\n\nIntérêt : la bobine est retrouvée même si son tag ne peut pas être déchiffré et ne fournit que l'UID de sa puce.",
    "Bambu 料盘两侧各有一枚 RFID 芯片。插件仅将打印机上报的数据填入第一个字段，第二个字段则留给其他读卡器使用。\n\n开启后：本秤会将贴近读卡器一侧的芯片 UID 写入两个槽位中的首个空位，已占用的槽位绝不会被覆盖。将料盘正反两面依次刷卡，即可填满两个槽位。\n\n作用：即使标签无法解密、仅能读出芯片 UID，依然能成功识别该料盘。" },  // STR_FLM_BTAGS_INFO

  { "external_id mitschreiben",
    "Write external_id too",
    "Écrire aussi external_id",
    "同步写入 external_id" },  // STR_FLM_EXTID
  { "verhindert doppelte Spulen",
    "stops duplicate spools",
    "évite les bobines en double",
    "防止生成重复料盘" },  // STR_FLM_EXTID_SUB
  { "Das Bambu-Plugin prüft vor dem Anlegen einer Spule nur external_id. Eine von der Waage verknüpfte Spule trägt die Tray-UUID aber in rfid_uid und ist für diese Prüfung unsichtbar - sie wird ein zweites Mal angelegt.\n\nAn: die Waage trägt bambulab:<Tray-UUID> nach, solange das Feld leer ist. Damit hören die Doppel auf.\n\nDer Preis: das Plugin behandelt die Spule danach als seine und schreibt das Restgewicht aus der AMS-Schätzung fort. Bis zur nächsten Wägung steht dann eine Schätzung dort, wo ein gemessener Wert stand.",
    "Before creating a spool the Bambu plugin looks at external_id and nothing else. A spool linked by this scale carries the tray uuid in rfid_uid instead and is invisible to that check, so it gets created a second time.\n\nOn: the scale fills in bambulab:<tray uuid> while the field is empty. That ends the duplicates.\n\nThe price: the plugin then treats the spool as its own and maintains the remaining weight from the AMS estimate. Until the next weighing an estimate stands where a measured value stood.",
    "Avant de créer une bobine, le module Bambu ne vérifie que external_id. Or une bobine liée par la balance porte l'identifiant Tray-UUID dans rfid_uid : ce contrôle ne la voit pas, et elle est créée une seconde fois.\n\nActivé : la balance inscrit bambulab:<Tray-UUID> tant que le champ est vide. Il n'y a plus de doublons.\n\nL'inconvénient : le module considère ensuite la bobine comme la sienne et met à jour son poids restant d'après l'estimation de l'AMS. Jusqu'à la pesée suivante, ce poids est une estimation et non une mesure.",
    "Bambu 插件在创建新料盘前仅检查 external_id 字段。而通过本秤绑定的料盘将托盘 UUID 存放在 rfid_uid 中，插件无法识别，从而导致重复创建料盘。\n\n开启后：当 external_id 为空时，本秤会自动填入 bambulab:<Tray-UUID>，从而杜绝重复创建。\n\n代价：插件随后会将该料盘视为自有料盘，并根据 AMS 估算值持续更新剩余重量。在下次重新称重前，页面显示的将是估算值而非实测值。" },  // STR_FLM_EXTID_INFO

  { "Tag gefunden - mehrere Spulen",
    "Tag found - several spools",
    "Tag trouvé - plusieurs bobines",
    "发现标签 - 匹配到多个料盘" },  // STR_TAG_FOUND_DUP

  // ---- device name --------------------------------------------------
  { "mDNS",
    "mDNS",
    "mDNS",
    "mDNS" },  // STR_W_R_MDNS
  { "Auch erreichbar über",
    "Also reachable at",
    "Également joignable à",
    "也可通过以下地址访问" },  // STR_W_DEVNAME_ALSO
  { "wird geprüft ...",
    "checking ...",
    "vérification ...",
    "正在检查..." },  // STR_W_DEVNAME_DNS_WAIT
  { "Der Name wird in deinem Netz aufgelöst und zeigt auf diese Waage.",
    "This name resolves on your network and points at this scale.",
    "Ce nom est résolu sur votre réseau et pointe vers cette balance.",
    "此名称已在局域网内解析，并指向当前秤。" },  // STR_W_DEVNAME_DNS_OK
  { "Der Name zeigt auf %s, nicht auf diese Waage.",
    "This name points at %s, not at this scale.",
    "Ce nom pointe vers %s, pas vers cette balance.",
    "此名称指向 %s，而非当前秤。" },  // STR_W_DEVNAME_DNS_OTHER
  { "Dein DNS-Server kennt diesen Namen nicht.",
    "Your DNS server does not know this name.",
    "Votre serveur DNS ne connaît pas ce nom.",
    "您的 DNS 服务器无法解析此名称。" },  // STR_W_DEVNAME_DNS_NONE
  { "Im lokalen Netz auf .local antworten (mDNS)",
    "Answer to .local on the local network (mDNS)",
    "Répondre en .local sur le réseau local (mDNS)",
    "在局域网内响应 .local 域名 (mDNS)" },  // STR_W_MDNS
  { "Findet die Waage ohne DNS-Server. Aus, wenn in deinem Netz kein .local laufen soll.",
    "Finds the scale with no DNS server involved. Off if your network should carry no .local traffic.",
    "Permet de trouver la balance sans serveur DNS. À désactiver si vous ne voulez pas de noms en .local sur votre réseau.",
    "无需 DNS 服务器即可发现此秤。若不希望局域网内存在 .local 流量，请关闭此项。" },  // STR_W_MDNS_HINT

  // Spool status (FilaMan). Id 6 is covered by STR_ARCHIVED above.
  { "Status wählen", "Select status", "Choisir le statut", "选择状态" },  // STR_STATUS_TITLE
  { "Neu",           "New",           "Neuve",             "全新" },  // STR_STATUS_NEW
  { "Geöffnet",      "Opened",        "Ouverte",           "已拆封" },  // STR_STATUS_OPENED
  { "Trocknet",      "Drying",        "Séchage",           "烘干中" },  // STR_STATUS_DRYING
  { "Aktiv",         "Active",        "Active",            "使用中" },  // STR_STATUS_ACTIVE
  { "Leer",          "Empty",         "Vide",              "空" },  // STR_STATUS_EMPTY
  { "Unbekannt",     "Unknown",       "Inconnu",           "未知" },  // STR_STATUS_UNKNOWN

  // Writing a tag
  { "Beschreiben + verknüpfen", "Write + link", "Écrire + lier", "写入并绑定" },  // STR_REMOTE_LINK_WRITE
  { "Tag im Format %s beschreiben und mit dieser Spule verknüpfen?",
    "Write the tag as %s and link it to this spool?",
    "Écrire le tag en %s et le lier à la bobine ?",
    "将标签写入为 %s 格式并绑定到此料盘？" },  // STR_REMOTE_LINK_Q_WRITE
  { "Tag beschreiben?", "Write tag?", "Écrire le tag ?", "写入标签？" },  // STR_TW_ASK_TITLE
  { "Der Tag wird im Format %s beschrieben. Was jetzt darauf steht, geht verloren.",
    "The tag is written as %s. Whatever is on it now is lost.",
    "Le tag sera écrit au format %s. Son contenu actuel sera perdu.",
    "标签将写入为 %s 格式，原有数据将被覆盖。" },  // STR_TW_ASK_HINT
  { "Beschreiben",            "Write",                "Écrire",                   "写入" },  // STR_TW_BTN_WRITE
  { "Nicht jetzt",            "Not now",              "Pas maintenant",           "暂不" },  // STR_TW_BTN_SKIP
  { "Tag beschrieben",        "Tag written",          "Tag écrit",                "标签已写入" },  // STR_TW_OK
  { "Kein Tag auf dem Leser", "No tag on the reader", "Aucun tag sur le lecteur",
    "读卡器上未检测到标签" },  // STR_TW_ERR_NO_TAG
  { "Dieser Tag ist nur lesbar", "This tag can only be read",
    "Ce tag est en lecture seule",
    "此标签仅支持读取" },  // STR_TW_ERR_NOT_NTAG
  { "Spule nicht abrufbar", "Spool could not be fetched",
    "Impossible de lire la bobine sur le serveur",
    "无法获取料盘信息" },  // STR_TW_ERR_BACKEND
  { "Der Tag ist zu klein für dieses Format. OpenSpool braucht einen NTAG215 mit 496 Byte, ein NTAG213 hat nur 144. Die Spule ist trotzdem mit dem Tag verknüpft - sie wird also erkannt, der Tag trägt nur keine Daten.",
    "This tag is too small for the format. OpenSpool wants an NTAG215 with 496 bytes, an NTAG213 holds only 144. The spool is linked to the tag all the same, so it is still recognised - the tag just carries no data.",
    "Ce tag est trop petit pour ce format. OpenSpool demande un NTAG215 de 496 octets, alors qu'un NTAG213 n'en a que 144. La bobine est tout de même liée au tag et sera donc reconnue, mais le tag ne contient aucune donnée.",
    "标签容量不足，无法写入此格式。OpenSpool 需要 496 字节的 NTAG215，而 NTAG213 仅有 144 字节。料盘仍已绑定至该标签，因此仍可正常识别，只是标签内未写入数据。" },  // STR_TW_ERR_SPACE
  { "Fehlgeschlagen - Tag still halten", "Failed - keep the tag still",
    "Échec - gardez le tag immobile",
    "写入失败 - 请保持标签静止" },  // STR_TW_ERR_WRITE
  { "Tag beim Trigger beschreiben", "Write tag on trigger",
    "Écrire le tag au déclenchement",
    "触发时写入标签" },  // STR_FLM_REMOTE_WRITE
  { "Nur wenn nicht gefragt wird", "Only when not asking",
    "Seulement si rien n'est demandé",
    "仅在跳过确认时生效" },  // STR_FLM_REMOTE_WRITE_SUB
  { "Wenn der Filament-Manager einen Schreibvorgang auslöst, fragt die Waage nach - dort kannst du zwischen Beschreiben und nur Verknüpfen wählen. Ohne Nachfrage (Verknüpfen ohne Rückfrage) gibt es diese Wahl nicht. Dieser Schalter entscheidet dann, ob ein beschreibbarer NTAG die Spulendaten bekommt oder nur verknüpft wird. Bambu-Tags sind nur lesbar und werden immer nur verknüpft.",
    "When the filament manager triggers a write, the scale writes the tag and links it in one step. With the prompt turned off (link without asking) that happens without any question at all. Off, the trigger only links, exactly as it did before. Bambu tags are read-only and are always only linked.",
    "Quand FilaMan demande l'écriture d'un tag, la balance écrit le tag et le lie à la bobine en une seule étape. Si l'option Lier sans demander est activée, tout se fait sans aucune question. Si ce réglage est désactivé, la demande ne fait que lier le tag, sans rien y écrire. Les tags Bambu sont en lecture seule et sont toujours seulement liés.",
    "当耗材管理器触发写入时，秤将一次性完成标签写入与绑定。若关闭确认提示（免确认直接绑定），则会直接执行而不再询问。关闭此项时，触发仅执行绑定，与之前一致。Bambu 标签为只读，始终仅作绑定。" },  // STR_FLM_REMOTE_WRITE_INFO
  { "%s passt nicht: %u Byte nötig, %u vorhanden. Dafür braucht es einen NTAG215.",
    "%s does not fit: %u bytes needed, %u available. That wants an NTAG215.",
    "%s ne convient pas : %u octets nécessaires, %u disponibles. Il faut un NTAG215.",
    "%s 格式无法写入：需要 %u 字节，当前可用 %u 字节，请使用 NTAG215 标签。" },  // STR_W_TAG_TOOSMALL

  // Results of a write or an erase
  { "Tag nicht beschrieben", "Tag not written", "Tag non écrit", "标签写入失败" },  // STR_TW_FAILED
  { "Die Spulendaten stehen jetzt im Format OpenSpool auf dem Tag.",
    "The spool data is now on the tag, as OpenSpool.",
    "Les données de la bobine sont maintenant sur le tag, au format OpenSpool.",
    "料盘数据已按 OpenSpool 格式写入标签。" },  // STR_TW_OK_INFO
  { "Tag auch löschen?", "Erase the tag too?", "Effacer aussi le tag ?", "同时擦除标签？" },  // STR_TW_ERASE_ASK_TITLE
  { "Die Verknüpfung ist gelöst. Der Tag trägt die Spulendaten aber weiter.",
    "The link is gone. The tag still carries the spool data though.",
    "La liaison est supprimée, mais le tag contient encore les données de la bobine.",
    "绑定已解除，但标签内仍存有料盘数据。" },  // STR_TW_ERASE_ASK_HINT
  { "Löschen",      "Erase",      "Effacer",    "擦除" },  // STR_TW_BTN_ERASE
  { "Behalten",     "Keep",       "Conserver",  "保留" },  // STR_TW_BTN_KEEP
  { "Tag gelöscht", "Tag erased", "Tag effacé", "标签已擦除" },  // STR_TW_ERASED
  { "Der Tag ist leer und kann neu beschrieben werden.",
    "The tag is empty and ready to be written again.",
    "Le tag est vide et prêt à être réécrit.",
    "标签已清空，可重新写入。" },  // STR_TW_ERASED_INFO
  { "Tag nicht gelöscht", "Tag not erased", "Tag non effacé", "标签擦除失败" },  // STR_TW_ERASE_FAILED
  { "OK",                 "OK",             "OK",             "OK" },  // STR_BTN_OK

  // Web access. The first line is an LVGL label and stays one row wide; the
  // other two are the web footer and carry HTML.
  { "Für diesen Schritt freigeschaltet",
    "Switched on for this step",
    "Activée pour cette étape",
    "已为此步骤临时开启" },  // STR_WEB_GATE_OPENED
  { "sind am Gerät ausgeschaltet und werden nicht ausgeliefert. Einschalten unter",
    "are switched off on the device and are not being served. Switch them on under",
    "sont désactivés sur l'appareil et ne sont pas servis. Activez-les dans",
    "已在设备上关闭，暂不提供访问。请在设备端开启：" },  // STR_W_FOOT_GATE_OFF
  { "Welche Bereiche ausgeliefert werden, entscheidet das Gerät unter",
    "Which sections are served is decided on the device under",
    "Les sections proposées se choisissent sur l'appareil, dans",
    "可访问的页面板块由设备端设置决定，路径：" },  // STR_W_FOOT_GATE_ALL


  // Backend options, mirrored in the browser
  { "Wird geladen ...",
    "Loading ...",
    "Chargement ...",
    "加载中 ..." },  // STR_W_LOADING
  { "am Gerät",
    "on the device",
    "sur l'appareil",
    "在设备上" },  // STR_W_ON_DEVICE
  { "Dieses Backend hat keine weiteren Optionen.",
    "This backend has no further options.",
    "Ce backend n'a pas d'autre option.",
    "此后端暂无更多选项。" },  // STR_W_NO_OPTIONS
  { "Filamentverwaltung",
    "Filament manager",
    "Gestion du filament",
    "耗材管理器" },  // STR_W_C_BACKEND
  { "Adresse, Zugangsdaten und Optionen gehören jeweils zu einer Verwaltung und bleiben beim Wechsel erhalten.",
    "Address, credentials and options belong to one manager each and survive a switch.",
    "L'adresse, les identifiants et les options sont propres à chaque gestionnaire, et restent enregistrés quand vous passez de l'un à l'autre.",
    "地址、凭据及选项按管理器独立保存，切换后仍会保留。" },  // STR_W_BACKEND_NOTE
  // %s is the name of the backend being switched to.
  { "Auf %s umschalten? Die Waage spricht danach mit einem anderen Bestand.",
    "Switch to %s? The scale will talk to a different inventory afterwards.",
    "Basculer vers %s ? La balance dialoguera ensuite avec un autre inventaire.",
    "切换至 %s？切换后秤将连接至不同的库存系统。" },  // STR_W_BACKEND_ASK
  { "Beim Auflegen aufwachen",
    "Wake when a spool is put down",
    "Réveiller l'écran à la pose d'une bobine",
    "放上料盘时自动唤醒" },  // STR_W_WAKE
  // Only the half a reader can act on. Why it is on by default is already in
  // the label; what belongs here is when to turn it off.
  { "Ausschalten, wenn die Waage neben etwas steht, das sie anstößt.",
    "Turn it off for a scale that shares a bench with something that knocks it.",
    "À désactiver si la balance est posée près de quelque chose qui la bouscule et risque de rallumer l'écran.",
    "若秤放置在易受震动或碰撞的台面上，请关闭此功能。" },  // STR_W_WAKE_HINT

  // Resetting the calibration, and the two refusals that keep a bad one from
  // being stored in the first place.
  { "Kalibrierung und Tara zurücksetzen?",
    "Reset calibration and tare?",
    "Réinitialiser l'étalonnage et la tare ?",
    "重置校准和去皮数据？" },  // STR_CAL_RESET_CONFIRM
  { "Referenz: 10 - 20000 g", "Reference: 10 - 20000 g", "Référence : 10 - 20000 g",
    "校准范围: 10 - 20000 g" },  // STR_CAL_RANGE_ERR
  { LV_SYMBOL_WARNING "  Messwert unplausibel, nicht gespeichert",
    LV_SYMBOL_WARNING "  Reading implausible, not saved",
    LV_SYMBOL_WARNING "  Mesure invraisemblable, non enregistrée",
    LV_SYMBOL_WARNING "  读数异常，未保存" },  // STR_CAL_IMPLAUSIBLE
  { "I2C-Bus",          "I2C bus",    "Bus I2C",             "I2C 总线" },  // STR_W_R_I2C
  { "Bus neu abfragen", "Rescan bus", "Réinterroger le bus", "重新扫描总线" },  // STR_W_RESCAN

  // ---- Writing a tag after a link ----
  { "Tag nach Verlinken beschreiben",
    "Write tag after linking",
    "Écrire le tag après la liaison",
    "绑定后写入标签" },  // STR_TW_OPT_ASK
  { "Was nach dem Verlinken einer Spule mit dem Tag geschieht. Beschrieben "
    "wird er vollständig, sein bisheriger Inhalt ist verloren.\n\n"
    "Aus: nur die UID wird mit der Spule verknüpft, der Tag bleibt unberührt. "
    "Beschreiben geht weiterhin über die Tag-Seite der Weboberfläche, wo "
    "vorher sichtbar ist, was auf den Tag geht.\n\n"
    "Fragen: die Waage fragt jedes Mal nach.\n\n"
    "Immer schreiben: ohne Rückfrage, nur das Ergebnis wird gemeldet.\n\n"
    "Geschrieben wird nur ein NTAG, der gross genug ist. Ein NTAG213 mit "
    "144 Byte ist für OpenSpool und FilaMan zu klein, NTAG215 und NTAG216 "
    "reichen. Bambu-Tags lassen sich nicht beschreiben.",
    "What happens to the tag once a spool is linked. Writing replaces its "
    "contents completely; whatever is on it now is lost.\n\n"
    "Off: only the UID is bound to the spool, the tag itself is left alone. "
    "Writing is still available on the tag page of the web interface, where "
    "what goes on the tag is visible beforehand.\n\n"
    "Ask: the scale asks every time.\n\n"
    "Write every time: no question, only the result is reported.\n\n"
    "Only an NTAG with room for the record is written. An NTAG213 with 144 "
    "bytes is too small for OpenSpool and FilaMan, NTAG215 and NTAG216 are "
    "not. Bambu tags cannot be written at all.",
    "Ce qui arrive au tag une fois la bobine liée. L'écriture remplace tout son contenu : ce qui s'y trouve actuellement est perdu.\n\nDésactivé : seul l'UID du tag est associé à la bobine, le tag lui-même reste intact. L'écriture reste possible depuis la page Tags de l'interface web, qui montre à l'avance ce qui sera écrit.\n\nDemander : la balance demande à chaque fois.\n\nÉcrire à chaque fois : aucune question, seul le résultat est affiché.\n\nSeul un NTAG assez grand est écrit. Un NTAG213 de 144 octets est trop petit pour OpenSpool et FilaMan ; un NTAG215 ou un NTAG216 suffit. Les tags Bambu ne peuvent pas être écrits.",
    "料盘绑定后对标签执行的操作。写入将完全覆盖原有内容，原有数据会丢失。\n\n关闭：仅将 UID 绑定至料盘，不修改标签内容。仍可在网页管理界面的标签页手动写入（写入前可预览数据）。\n\n询问：每次绑定时秤端都会弹出询问。\n\n总是写入：不询问，直接写入并提示结果。\n\n仅当 NTAG 容量足够容纳数据时才会写入。144 字节的 NTAG213 容量不足以写入 OpenSpool 和 FilaMan 格式，NTAG215 和 NTAG216 则支持。Bambu 标签完全无法写入。" },  // STR_TW_OPT_ASK_INFO
  { "Format", "Format", "Format", "格式" },  // STR_TW_OPT_FMT
  { "Das Format entscheidet, wer den Tag lesen kann.\n\n"
    "OpenSpool ist ein NDEF-Datensatz mit Material, Farbe, Marke, "
    "Temperaturen und der Spulen-ID, den FilaMan und OpenSpool-Leser "
    "verstehen.\n\n"
    "FilaMan ist derselbe Datensatz unter dem Protokollnamen, den eine "
    "FilaMan-Installation erwartet.\n\n"
    "Anycubic ACE schreibt keinen Datensatz, sondern rohe Seiten mit "
    "Artikelnummer, Marke, Material, Farbe, Düsen- und Betttemperatur, "
    "Durchmesser, Länge und Gewicht. Das liest die ACE selbst.",
    "The format decides who can read the tag.\n\n"
    "OpenSpool is an NDEF record carrying material, colour, brand, "
    "temperatures and the spool id, which FilaMan and OpenSpool readers "
    "understand.\n\n"
    "FilaMan is the same record under the protocol name a FilaMan "
    "installation expects.\n\n"
    "Anycubic ACE writes no record at all but raw pages holding SKU, brand, "
    "material, colour, nozzle and bed temperature, diameter, length and "
    "weight. The ACE reads those itself.",
    "Le format décide qui pourra lire le tag.\n\nOpenSpool est un enregistrement NDEF contenant le matériau, la couleur, la marque, les températures et l'ID de la bobine ; FilaMan et les lecteurs OpenSpool savent le lire.\n\nFilaMan est le même enregistrement, sous le nom de protocole qu'attend une installation FilaMan.\n\nAnycubic ACE n'écrit aucun enregistrement, mais des pages brutes contenant la référence article, la marque, le matériau, la couleur, les températures de buse et de plateau, le diamètre, la longueur et le poids. L'ACE les lit directement.",
    "格式决定了哪些设备可以读取该标签。\n\nOpenSpool 是一种 NDEF 记录，包含材质、颜色、品牌、温度及料盘 ID，FilaMan 和 OpenSpool 读卡器均可识别。\n\nFilaMan 为相同内容的记录，但采用 FilaMan 服务端所需的协议名称。\n\nAnycubic ACE 不写入 NDEF 记录，而是直接将 SKU、品牌、材质、颜色、喷嘴和热床温度、线径、长度及重量写入原始存储页，供 ACE 自行读取。" },  // STR_TW_OPT_FMT_INFO
  { "OpenSpool", "OpenSpool", "OpenSpool",
    "OpenSpool" },  // STR_TW_FMT_OPENSPOOL
  { "FilaMan", "FilaMan", "FilaMan",
    "FilaMan" },  // STR_TW_FMT_FILAMAN
  { "Anycubic ACE", "Anycubic ACE", "Anycubic ACE",
    "Anycubic ACE" },  // STR_TW_FMT_ACE
  { "Automatik an der Waage", "Automatic on the scale", "Actions automatiques de la balance",
    "秤端自动操作" },  // STR_W_C_TAGOPTS
  { "Nach dem Verlinken", "After linking", "Après la liaison",
    "绑定后" },  // STR_W_TAGOPT_ASK
  { "Format", "Format", "Format",
    "格式" },  // STR_W_TAGOPT_FMT
  { "Gilt für das, was die Waage nach einem Verlinken selbst tut. "
    "Das Schreiben auf dieser Seite hat seine eigene Formatauswahl.",
    "Applies to what the scale does on its own after a link. Writing from this "
    "page has its own format selector.",
    "Ces réglages concernent ce que la balance fait d'elle-même après avoir lié un tag à une bobine. L'écriture lancée depuis cette page a son propre choix de format, plus haut.",
    "适用于绑定后秤端自动执行的操作。在此页面手动写入时可单独选择格式。" },  // STR_W_TAGOPT_NOTE
  { "Speichern", "Download", "Enregistrer", "下载" },  // STR_W_LOG_DOWNLOAD
  { "Kein Material passte - Filter aufgehoben",
    "No material matched - filter dropped",
    "Aucun matériau ne correspondait - filtre levé",
    "无匹配材质 - 已清除筛选" },  // STR_LIST_MAT_IGNORED
  { "Bei Abweichung fragen", "Ask on a mismatch", "Demander en cas d'écart", "信息不符时询问" },  // STR_TW_OPT_MISM
  { "Wenn der Tag nicht zur Spule passt",
    "When the tag disagrees with the spool",
    "Si le tag ne correspond pas à la bobine",
    "当标签与料盘信息不一致时" },  // STR_TW_OPT_MISM_SUB
  { "Trägt der Tag ein anderes Material, eine andere Marke oder eine deutlich "
    "andere Farbe als die verknüpfte Spule, bietet die Waage an, ihn neu zu "
    "beschreiben. Verglichen wird nur der Inhalt, nicht das Format. Aus "
    "bleibt der Tag unangetastet.",
    "If the tag carries a different material, brand or a clearly different "
    "colour than the spool it is bound to, the scale offers to write it again. "
    "Only the contents are compared, not the format. Off leaves the tag "
    "untouched.",
    "Si le tag indique un autre matériau, une autre marque ou une couleur nettement différente de celle de la bobine liée, la balance propose de le réécrire. Seul le contenu est comparé, pas le format. Désactivé : le tag reste intact.",
    "若标签内的材质、品牌或颜色与所绑定料盘存在明显差异，秤端将提示是否重新写入。仅比对数据内容，不比对格式。关闭则保留标签原样。" },  // STR_TW_OPT_MISM_INFO
  { "Tag weicht ab",   "Tag disagrees", "Le tag ne correspond pas", "标签信息不符" },  // STR_TW_MISM_TITLE
  { "%s",              "%s",            "%s",                       "%s" },  // STR_TW_MISM_HINT
  { "Neu beschreiben", "Write again",   "Réécrire",                 "重新写入" },  // STR_TW_BTN_REWRITE
  { "Tag",             "Tag",           "Tag",                      "Tag" },  // STR_TW_MISM_TAG
  { "Server",          "Server",        "Serveur",                  "服务器" },  // STR_TW_MISM_SERVER
  { "An der Waage fragen, wenn der Tag nicht zur Spule passt",
    "Ask at the scale when the tag disagrees with the spool",
    "Demander sur la balance quand le tag ne correspond pas à la bobine",
    "当标签与料盘信息不符时在秤端询问" },  // STR_W_TAGOPT_MISM
  { "Spule %d wird geschrieben...", "Writing spool %d...", "Écriture de la bobine %d...",
    "正在写入料盘 %d..." },  // STR_W_TW_WRITING
  { "Tag wird geleert...", "Erasing the tag...", "Effacement du tag...",
    "正在擦除标签..." },  // STR_W_TW_ERASING
  { "Spule %d (%s) als %s geschrieben",
    "Wrote spool %d (%s) as %s",
    "Tag écrit pour la bobine %d (%s) au format %s",
    "已将料盘 %d (%s) 写入为 %s 格式" },  // STR_W_TW_WROTE
  { ", verknüpft",      ", linked to the spool", ", lié à la bobine",      "，已绑定至料盘" },  // STR_W_TW_LINKED
  { ", verknüpft (%s)", ", linked (%s)",         ", liaison établie (%s)", "，已绑定 (%s)" },  // STR_W_TW_LINKED_NOTE
  { ", aber das Verknüpfen schlug fehl (HTTP %d)",
    ", but linking failed (HTTP %d)",
    ", mais la liaison a échoué (HTTP %d)",
    "，但绑定失败 (HTTP %d)" },  // STR_W_TW_LINK_FAIL
  { "Tag geleert", "Tag erased", "Tag effacé", "标签已擦除" },  // STR_W_TW_ERASED
  { "Löschen fehlgeschlagen - Tag ruhig halten",
    "Erase failed - keep the tag still",
    "Échec de l'effacement - gardez le tag immobile",
    "擦除失败 - 请保持标签静止" },  // STR_W_TW_ERASE_FAIL
  { "MIFARE Classic, nur lesbar", "MIFARE Classic, read-only",
    "MIFARE Classic, lecture seule",
    "MIFARE Classic，只读" },  // STR_W_TAG_KIND_MIFARE
  { "NTAG, beschreibbar", "NTAG, writable",    "NTAG, inscriptible",   "NTAG，可写" },  // STR_W_TAG_KIND_NTAG
  { ", %u Byte",          ", %u bytes",        ", %u octets",          "，%u 字节" },  // STR_W_TAG_KIND_BYTES
  { "Gebunden über: %s",  "Bound through: %s", "Liée via : %s",        "绑定方式：%s" },  // STR_UNLINK_SOURCES
  { "Aus",                "Off",               "Désactivé",            "关" },  // STR_TW_MODE_OFF
  { "Fragen",             "Ask",               "Demander",             "询问" },  // STR_TW_MODE_ASK
  { "Immer schreiben",    "Write every time",  "Écrire à chaque fois", "每次都写入" },  // STR_TW_MODE_ALWAYS

  // ---- Hardware self diagnosis -----------------------------------------
  { "  -  antippen", "  -  tap for help", "  -  touchez ici",   " -  点击查看帮助" },  // STR_DIAG_TAP
  { "Später",        "Later",             "Plus tard",          "稍后" },  // STR_DIAG_BTN_LATER
  { "Erneut prüfen", "Check again",       "Vérifier à nouveau", "重新检查" },  // STR_DIAG_BTN_RECHECK

  { "Kein Modul am I2C-Bus", "Nothing on the I2C bus", "Rien sur le bus I2C",
    "I2C 总线上无设备" },  // STR_DIAG_BUS_EMPTY_BANNER
  { "Kein Modul am I2C-Bus", "Nothing on the I2C bus", "Rien sur le bus I2C",
    "I2C 总线上无设备" },  // STR_DIAG_BUS_EMPTY_TITLE
  { "Weder der NFC-Reader noch der Waagen-ADC antworten.\n\n"
    "Das 7-polige Kabel muss bündig links in der 8-poligen I/O-Buchse sitzen. "
    "Ein Pin daneben und beide Module sind stromlos.\n\n"
    "Prüfe Pin 1 (5V, rot), Pin 2 (GND, schwarz), Pin 3 (SDA, gelb) und "
    "Pin 4 (SCL, grün).",
    "Neither the NFC reader nor the scale ADC answers.\n\n"
    "The 7 pin cable has to sit flush to the left in the 8 pin I/O socket. "
    "One pin off and both modules are unpowered.\n\n"
    "Check pin 1 (5V, red), pin 2 (GND, black), pin 3 (SDA, yellow) and "
    "pin 4 (SCL, green).",
    "Ni le lecteur NFC ni le convertisseur de la balance (NAU7802) ne répondent.\n\nDans la prise I/O à 8 broches, le câble à 7 broches doit être aligné sur le côté gauche. Décalé d'une seule broche, il n'alimente plus aucun des deux modules.\n\nVérifiez la broche 1 (5V, rouge), la broche 2 (GND, noir), la broche 3 (SDA, jaune) et la broche 4 (SCL, vert).",
    "NFC 读卡器和秤 ADC 均无响应。\n\n7 针排线必须靠左齐平插入 8 针 I/O 接口，错开一针会导致两个模块均无供电。\n\n请检查引脚 1 (5V, 红)、2 (GND, 黑)、3 (SDA, 黄) 和 4 (SCL, 绿)。" },  // STR_DIAG_BUS_EMPTY_TEXT

  { "Waagen-ADC fehlt (NAU7802)", "Scale ADC missing (NAU7802)",
    "Convertisseur absent (NAU7802)",
    "缺少秤 ADC (NAU7802)" },  // STR_DIAG_NAU_MISSING_BANNER
  { "Waagen-ADC fehlt", "Scale ADC missing",
    "Convertisseur de la balance absent",
    "缺少秤 ADC" },  // STR_DIAG_NAU_MISSING_TITLE
  { "Die NAU7802 antwortet nicht auf 0x2A. Der NFC-Reader schon, SDA und SCL "
    "sind also grundsätzlich in Ordnung.\n\n"
    "Prüfe VIN, GND, SDA und SCL an der NAU7802.\n\n"
    "Bei fertigen STEMMA-QT-Kabeln von Drittanbietern stimmt die "
    "Pinreihenfolge oft nicht mit der des WT32-Kabels überein.\n\n"
    "Ist dieses Gerät bewusst ohne Waage gebaut, schalte sie unter "
    "Einstellungen > Waage ab - dann verschwindet diese Meldung.",
    "The NAU7802 does not answer on 0x2A. The NFC reader does, so SDA and SCL "
    "are basically fine.\n\n"
    "Check VIN, GND, SDA and SCL on the NAU7802.\n\n"
    "On third party STEMMA QT cables the pin order often does not match the "
    "WT32 cable.\n\n"
    "If this device was deliberately built without a scale, switch it off "
    "under Settings > Scale and this finding goes away.",
    "Le NAU7802 ne répond pas à l'adresse 0x2A. Le lecteur NFC, lui, répond : les fils SDA et SCL sont donc bons en principe.\n\nVérifiez les fils VIN, GND, SDA et SCL sur le NAU7802.\n\nSur les câbles STEMMA QT tout faits d'autres fabricants, l'ordre des broches diffère souvent de celui du câble WT32.\n\nSi cet appareil est volontairement monté sans balance, désactivez « Balance présente » dans Réglages > Balance : ce message disparaîtra.",
    "NAU7802 在 0x2A 地址无响应。NFC 读卡器正常，说明 SDA 和 SCL 基本连接无误。\n\n请检查 NAU7802 上的 VIN、GND、SDA 和 SCL。\n\n第三方 STEMMA QT 线缆的线序常与 WT32 线缆不一致。\n\n若此设备本就未装秤，请在“设置 > 秤”中关闭，此提示将消失。" },  // STR_DIAG_NAU_MISSING_TEXT

  { "NFC-Reader fehlt (PN532)", "NFC reader missing (PN532)",
    "Lecteur NFC absent (PN532)",
    "缺少 NFC 读卡器 (PN532)" },  // STR_DIAG_PN532_MISSING_BANNER
  { "NFC-Reader fehlt", "NFC reader missing", "Lecteur NFC absent", "缺少 NFC 读卡器" },  // STR_DIAG_PN532_MISSING_TITLE
  { "Der PN532 antwortet nicht auf 0x24. Der Waagen-ADC schon, SDA und SCL "
    "sind also grundsätzlich in Ordnung.\n\n"
    "Prüfe zuerst die beiden DIP-Schalter auf dem Modul: für I2C muss "
    "SW1 = ON und SW2 = OFF stehen. In der HSU- oder SPI-Stellung meldet sich "
    "der Chip auf dem I2C-Bus überhaupt nicht - genau dieses Bild.\n\n"
    "Sonst braucht der PN532 5V von Pin 1 des I/O-Kabels. Schließe ihn nicht "
    "über den STEMMA-QT-Durchgang der NAU7802 an - der führt nur 3,3V.",
    "The PN532 does not answer on 0x24. The scale ADC does, so SDA and SCL "
    "are basically fine.\n\n"
    "Check the two DIP switches on the module first: I2C needs SW1 = ON and "
    "SW2 = OFF. Set to HSU or SPI the chip does not answer on the I2C bus at "
    "all - which is exactly what is happening here.\n\n"
    "Otherwise the PN532 needs 5V from pin 1 of the I/O cable. Do not daisy "
    "chain it through the NAU7802 STEMMA QT passthrough - that one only "
    "carries 3.3V.",
    "Le PN532 ne répond pas à l'adresse 0x24. Le convertisseur de la balance, lui, répond : les fils SDA et SCL sont donc bons en principe.\n\nVérifiez d'abord les deux interrupteurs DIP du module : pour l'I2C, SW1 doit être sur ON et SW2 sur OFF. En position HSU ou SPI, la puce ne répond pas du tout sur le bus I2C - c'est exactement le symptôme observé.\n\nSinon, le PN532 doit recevoir le 5V de la broche 1 du câble I/O. Ne le branchez pas à la suite du NAU7802, par le connecteur STEMMA QT de celui-ci : ce connecteur ne fournit que du 3,3V.",
    "PN532 在 0x24 地址无响应。秤 ADC 正常，说明 SDA 和 SCL 基本连接无误。\n\n请先检查模块上的两个拨码开关：I2C 模式需设 SW1 = ON 且 SW2 = OFF。若拨至 HSU 或 SPI，芯片在 I2C 总线上完全不会响应（正是当前状况）。\n\n此外，PN532 需从 I/O 排线引脚 1 获取 5V 供电，切勿通过 NAU7802 的 STEMMA QT 接口串联，该接口仅提供 3.3V。" },  // STR_DIAG_PN532_MISSING_TEXT

  { "NFC-Reader antwortet nicht", "NFC reader does not answer",
    "Le lecteur NFC ne répond pas",
    "NFC 读卡器无响应" },  // STR_DIAG_PN532_MUTE_BANNER
  { "NFC-Reader meldet sich nicht", "NFC reader stays silent",
    "Le lecteur NFC reste muet",
    "NFC 读卡器无应答" },  // STR_DIAG_PN532_MUTE_TITLE
  { "Der PN532 bestätigt 0x24, beantwortet aber keinen Befehl. Er steht damit "
    "auf I2C - sonst würde er sich gar nicht melden - und SDA und SCL "
    "stimmen ebenfalls.\n\n"
    "Prüfe zuerst die beiden DIP-Schalter: für I2C muss SW1 = ON und SW2 = OFF "
    "stehen. Ein Schalter zwischen zwei Stellungen ist die häufigste Ursache.\n\n"
    "Prüfe dann die 5V an Pin 1. Zu wenig Spannung lässt den Chip sich am Bus "
    "melden, ohne dass er arbeiten kann.\n\n"
    "Einen Reset zum Ziehen gibt es hier nicht: der orange RST-Draht liegt auf "
    "einem Ausgang des Moduls statt auf dessen Reset-Eingang. Aus- und wieder "
    "einstecken ist der einzige harte Reset.",
    "The PN532 acknowledges 0x24 but answers no command. That means it is set "
    "to I2C - it would not answer at all otherwise - and SDA and SCL are "
    "right too.\n\n"
    "Check the two DIP switches first: I2C needs SW1 = ON and SW2 = OFF. A "
    "switch resting between positions is the most common cause.\n\n"
    "Then check the 5V on pin 1. Too little supply lets the chip announce "
    "itself on the bus without being able to work.\n\n"
    "There is no reset to pull here: the orange RST wire sits on an output of "
    "the module rather than its reset input. Unplugging and replugging is the "
    "only hard reset there is.",
    "Le PN532 se signale à l'adresse 0x24, mais ne répond à aucune commande. Il est donc bien réglé en I2C - sinon il ne se signalerait pas du tout - et les fils SDA et SCL sont bons eux aussi.\n\nVérifiez d'abord les deux interrupteurs DIP : pour l'I2C, SW1 doit être sur ON et SW2 sur OFF. Un interrupteur resté entre deux positions est la cause la plus fréquente.\n\nVérifiez ensuite le 5V sur la broche 1. Avec une tension trop faible, la puce se signale sur le bus sans pouvoir fonctionner.\n\nIci, la balance ne peut pas réinitialiser la puce par un signal : le fil orange RST est relié à une sortie du module, et non à son entrée de réinitialisation. Débrancher puis rebrancher est la seule réinitialisation matérielle possible.",
    "PN532 应答了 0x24 地址，但不响应任何指令。这说明它已设为 I2C 模式（否则根本不会应答），且 SDA 和 SCL 接线正确。\n\n请先检查两个拨码开关：I2C 模式需设 SW1 = ON 且 SW2 = OFF，开关卡在中间位置是最常见原因。\n\n接着检查引脚 1 的 5V 供电，电压不足会导致芯片虽能在总线上报到却无法工作。\n\n此处无法通过引脚复位：橙色 RST 线接在模块输出端而非复位输入端，断电重插是唯一的硬复位方式。" },  // STR_DIAG_PN532_MUTE_TEXT

  { "Nicht kalibriert: Gewicht stimmt nicht", "Not calibrated: weight is wrong",
    "Non étalonnée : poids inexact",
    "未校准：重量不准" },  // STR_DIAG_UNCAL_BANNER
  { "Waage nicht kalibriert", "Scale not calibrated",
    "Balance non étalonnée",
    "秤未校准" },  // STR_DIAG_UNCAL_TITLE
  { "Das angezeigte Gewicht ist nur ein grober Näherungswert und kann weit "
    "danebenliegen. Speichere es besser noch nicht im Inventar.\n\n"
    "Das ist kein Defekt und kein Verkabelungsfehler. Die Waage weiß nur noch "
    "nicht, wie viele Messschritte ein Gramm sind.\n\n"
    "Lege ein bekanntes Gewicht auf und kalibriere sie.",
    "The weight on screen is only a rough estimate and can be far off. Better "
    "not save it to your inventory yet.\n\n"
    "This is neither a defect nor a wiring mistake. The scale simply does not "
    "know yet how many counts make a gram.\n\n"
    "Place a known weight on it and calibrate.",
    "Le poids affiché n'est qu'une estimation grossière et peut être très éloigné de la réalité. Mieux vaut ne pas encore l'enregistrer dans l'inventaire.\n\nCe n'est ni une panne ni une erreur de câblage. La balance ne sait simplement pas encore à combien d'unités brutes correspond un gramme.\n\nPosez un poids connu sur le plateau et étalonnez la balance.",
    "屏幕显示的重量仅为粗略估算，可能偏差较大，建议暂勿存入库存。\n\n这并非故障或接线错误，只是秤尚未确定多少计数对应 1 克。\n\n请放上已知重量的物体进行校准。" },  // STR_DIAG_UNCAL_TEXT

  { "Wägezelle verpolt (A+/A-)", "Load cell reversed (A+/A-)",
    "Capteur de pesée inversé (A+/A-)",
    "称重传感器反接 (A+/A-)" },  // STR_DIAG_INVERTED_BANNER
  { "Wägezelle verpolt", "Load cell reversed",
    "Capteur de pesée inversé",
    "称重传感器反接" },  // STR_DIAG_INVERTED_TITLE
  { "Die Waage liest bei leerer Plattform stark negativ und hat seit dem Start "
    "nie ein positives Gewicht gesehen. Auflegen macht die Zahl kleiner statt "
    "größer.\n\n"
    "Tausche an der NAU7802 die beiden Signaladern: A+ (weiß) und A- (grün).\n\n"
    "Danach neu tarieren und kalibrieren.",
    "The scale reads far below zero with an empty platform and has never seen "
    "a positive weight since it started. Loading it makes the number go down "
    "instead of up.\n\n"
    "Swap the two signal wires on the NAU7802: A+ (white) and A- (green).\n\n"
    "Then tare and calibrate again.",
    "À vide, la balance affiche une valeur très négative et n'a mesuré aucun poids positif depuis le démarrage. Poser un objet la fait baisser au lieu de l'augmenter.\n\nInversez les deux fils de signal sur le NAU7802 : A+ (blanc) et A- (vert).\n\nRefaites ensuite la tare et l'étalonnage.",
    "空盘时读数远低于零，且开机以来从未出现过正值；放上重物时数值反而减小。\n\n请对调 NAU7802 上的两根信号线：A+（白）与 A-（绿）。\n\n然后重新去皮并校准。" },  // STR_DIAG_INVERTED_TEXT

  { "Wägezelle unruhig", "Load cell unstable", "Capteur de pesée instable", "称重传感器读数不稳" },  // STR_DIAG_NOISY_BANNER
  { "Wägezelle unruhig", "Load cell unstable", "Capteur de pesée instable", "称重传感器读数不稳" },  // STR_DIAG_NOISY_TITLE
  { "Der Messwert schwankt dauerhaft um mehr als %d g, obwohl auf der "
    "Plattform nichts bewegt wird.\n\n"
    "Das ist typisch für eine lose Ader an der NAU7802. Prüfe E+ (rot), "
    "E- (schwarz), A+ (weiß) und A- (grün) auf kalte Lötstellen.\n\n"
    "Prüfe außerdem, ob ein Kabel gegen die Wiegeplattform drückt.",
    "The reading keeps swinging by more than %d g although nothing on the "
    "platform is moving.\n\n"
    "That is typical for a loose wire on the NAU7802. Check E+ (red), "
    "E- (black), A+ (white) and A- (green) for cold solder joints.\n\n"
    "Also check whether a cable is pressing against the weighing platform.",
    "La mesure varie en permanence de plus de %d g alors que rien ne bouge sur le plateau.\n\nC'est typique d'un fil mal fixé sur le NAU7802. Vérifiez E+ (rouge), E- (noir), A+ (blanc) et A- (vert), à la recherche d'une soudure froide.\n\nVérifiez aussi qu'aucun câble n'appuie contre le plateau de pesée.",
    "秤盘上无物体移动，但读数持续波动超过 %d g。\n\n这通常是 NAU7802 接线松动所致，请检查 E+（红）、E-（黑）、A+（白）和 A-（绿）是否存在虚焊。\n\n同时检查是否有线缆顶住了称重台。" },  // STR_DIAG_NOISY_TEXT

  { "So kalibrierst du", "How to calibrate", "Comment étalonner", "如何校准" },  // STR_CAL_HELP_TITLE
  { "1. Plattform leer räumen und auf Nullen drücken. Die Anzeige muss auf 0 gehen.\n\n"
    "2. Ein Gewicht auflegen, das du genau kennst. Ideal sind etwa 1000 g - "
    "eine volle Spule, auf einer Küchenwaage nachgewogen, reicht völlig.\n\n"
    "3. Dieses Gewicht in Gramm eintippen und auf Berechnen drücken.\n\n"
    "Je genauer das Referenzgewicht, desto genauer misst die Waage danach.",
    "1. Clear the platform and press Zero. The reading has to go to 0.\n\n"
    "2. Place a weight you know exactly. Around 1000 g is ideal - a full spool "
    "checked on a kitchen scale is plenty.\n\n"
    "3. Type that weight in grams and press Calculate.\n\n"
    "The more precise the reference weight, the more accurate the scale is "
    "afterwards.",
    "1. Videz le plateau et appuyez sur Mettre à zéro. L'affichage doit passer à 0.\n\n2. Posez un poids que vous connaissez exactement. L'idéal est un poids d'environ 1000 g - une bobine pleine, pesée sur une balance de cuisine, suffit amplement.\n\n3. Saisissez ce poids en grammes et appuyez sur Calculer.\n\nPlus le poids de référence est précis, plus les mesures de la balance seront précises ensuite.",
    "1. 清空秤盘并按“归零”，读数必须变为 0。\n\n2. 放上已知准确重量的物体，约 1000 g 最理想（用厨房秤称过的满盘耗材即可）。\n\n3. 输入该重量（克）并按“计算”。\n\n参考重量越精确，校准后的称重就越准确。" },  // STR_CAL_HELP_TEXT

  { "Diagnose",    "Diagnosis",     "Diagnostic",      "诊断" },  // STR_W_R_DIAG
  { "ohne Befund", "nothing found", "rien à signaler", "未发现异常" },  // STR_W_S_DIAG_OK

  // ---- PN532 reset line, the optional hardware modification ----
  { "Hardware-Umbau möglich", "A hardware change is available",
    "Modification matérielle possible",
    "支持硬件改装" },  // STR_NFCRST_HINT_TITLE
  { "Der NFC-Leser dieser Waage musste schon einmal neu gestartet werden.\n\n"
    "Dagegen gibt es einen optionalen Umbau: der orange RST-Draht gehört auf "
    "RSTPDN. Dann kann die Waage den Leser wirklich zurücksetzen.\n\n"
    "Anleitung in der Doku unter Verkabelung. Prüfen danach unter "
    "System > NFC-Reset prüfen. Es geht nichts kaputt, wenn du es lässt.",
    "The NFC reader on this scale has had to be restarted at least once.\n\n"
    "There is an optional change against it: the orange RST wire belongs on "
    "RSTPDN. The scale can then genuinely reset the reader.\n\n"
    "Guide in the docs under Wiring. Check afterwards under System > Check NFC "
    "reset. Nothing breaks if you leave it.",
    "Le lecteur NFC de cette balance a déjà dû être redémarré au moins une fois.\n\nUne modification facultative y remédie : déplacer le fil orange RST sur RSTPDN. La balance pourra alors vraiment réinitialiser le lecteur.\n\nLa marche à suivre se trouve dans la documentation, section Wiring (câblage). Contrôlez ensuite le résultat dans Système > Vérifier la réinit. NFC. Si vous ne faites pas cette modification, rien ne sera endommagé.",
    "此秤的 NFC 读卡器已至少重启过一次。\n\n可通过可选的硬件改动解决：将橙色 RST 线改接到 RSTPDN，秤即可真正复位读卡器。\n\n详见文档“接线”章节，改完后在“系统 > 检查 NFC 复位”中验证。不改也不会损坏设备。" },  // STR_NFCRST_HINT_TEXT
  { "Später",              "Later",             "Plus tard",        "稍后" },  // STR_NFCRST_LATER
  { "Nicht mehr anzeigen", "Do not show again", "Ne plus afficher", "不再显示" },  // STR_NFCRST_NEVER

  { "NFC-Reset prüfen", "Check NFC reset", "Vérifier la réinit. NFC",
    "检查 NFC 复位" },  // STR_NFCRST_ROW
  { "Nach dem Umlöten", "After the rewiring", "Après la modification du câblage",
    "重新接线后" },  // STR_NFCRST_ROW_SUB
  { "Leitung geprüft, aktiv", "Line verified, in use", "Liaison vérifiée, active",
    "线路已验证并启用" },  // STR_NFCRST_ROW_DONE
  { "Reset-Leitung sitzt", "Reset line is there",
    "Liaison de réinitialisation présente",
    "复位线已就绪" },  // STR_NFCRST_OK_TITLE
  { "Der Leser hat auf die Leitung reagiert. Ab dem nächsten Start benutzt "
    "die Waage den Hardware-Reset.",
    "The reader responded to the line. From the next start the scale uses the "
    "hardware reset.",
    "Le lecteur a réagi à la liaison. Dès le prochain démarrage, la balance utilisera la réinitialisation matérielle.",
    "读卡器已响应复位信号，下次启动起将启用硬件复位。" },  // STR_NFCRST_OK_TEXT
  { "Keine Wirkung", "No effect", "Aucun effet", "无效果" },  // STR_NFCRST_FAIL_TITLE
  { "Der Leser hat nichts gemerkt. Der orange Draht liegt noch auf dem alten "
    "Pad, oder die Lötstelle hat keinen Kontakt.\n\n"
    "Es ändert sich nichts, die Waage arbeitet weiter wie bisher.",
    "The reader did not notice. The orange wire is still on the old pad, or "
    "the joint is not making contact.\n\n"
    "Nothing changes, the scale carries on as before.",
    "Le lecteur n'a pas réagi au test de réinitialisation. Soit le fil orange est encore sur l'ancienne pastille, soit la soudure ne fait pas contact.\n\nRien n'est modifié : la balance continue de fonctionner comme avant.",
    "读卡器未检测到信号。橙色线可能仍接在旧焊盘上，或焊点接触不良。\n\n设置未作更改，秤将继续按原方式运行。" },  // STR_NFCRST_FAIL_TEXT

  // ── Hardware UID into extra.rfid_tag ──
  { "Chip-UID mitschreiben", "Also write the chip UID", "Écrire aussi l'UID de la puce",
    "同时写入芯片 UID" },  // STR_HW_UID_WRITE
  { "Zusätzlich in rfid_tag", "Into rfid_tag as well", "Également dans rfid_tag",
    "也写入 rfid_tag" },  // STR_HW_UID_WRITE_SUB
  { "An: die Hardware-UID des Chips, der gerade auf dem Leser liegt, kommt "
    "zusätzlich in das Extra-Feld rfid_tag, als kommagetrennte Liste. Die "
    "Bindung selbst bleibt unverändert in dem Feld, das oben gewählt ist.\n\n"
    "Happy Hare an einem Voron liest ausschließlich rfid_tag, und die Leser "
    "an den Gates sehen nur die Hardware-UID des Chips, nie die tray_uuid "
    "einer Bambu-Spule. Ohne dieses Feld findet der Drucker die Spule nicht, "
    "die auf der Waage längst erkannt wird.\n\n"
    "Eine Bambu-Spule trägt zwei Chips, also zwei UIDs. Die Liste wächst von "
    "selbst: einmal jede Seite auflegen, danach antwortet die Spule an beiden "
    "Gates.\n\n"
    "Die Waage schreibt dabei in jede Spule, die sie erkennt, nicht erst beim "
    "Verknüpfen. Steht die UID schon drin, geht keine Anfrage mehr raus. Fehlt "
    "das Feld, legt die Waage es beim ersten Schreiben an.",
    "On: the hardware UID of the chip currently on the reader goes into the "
    "rfid_tag extra field as well, as a comma separated list. The binding "
    "itself stays untouched in the field selected above.\n\n"
    "Happy Hare on a Voron reads rfid_tag and nothing else, and the readers at "
    "its gates only ever see the chip's hardware UID, never the tray_uuid of a "
    "Bambu spool. Without this field the printer cannot find the spool the "
    "scale recognises perfectly well.\n\n"
    "A Bambu spool carries two chips and therefore two UIDs. The list grows on "
    "its own: put each side on the reader once and the spool answers at both "
    "gates.\n\n"
    "The scale writes this into every spool it recognises, not only when a "
    "link is made. Once the UID is in there, no request goes out again. If the "
    "field is missing, the scale creates it on the first write.",
    "Activé : l'UID matériel de la puce posée sur le lecteur est aussi ajouté au champ supplémentaire rfid_tag, dans une liste séparée par des virgules. La liaison elle-même reste inchangée, dans le champ choisi plus haut.\n\nSur une Voron, Happy Hare ne lit que rfid_tag, et les lecteurs placés à ses entrées (gates) ne voient que l'UID matériel de la puce, jamais la tray_uuid d'une bobine Bambu. Sans ce champ, l'imprimante ne trouve pas une bobine que la balance reconnaît pourtant très bien.\n\nUne bobine Bambu porte deux puces, donc deux UID. La liste se complète toute seule : posez une fois chaque côté de la bobine sur le lecteur, et elle sera reconnue aux deux entrées.\n\nLa balance renseigne ce champ pour chaque bobine qu'elle reconnaît, pas seulement lors d'une liaison. Si l'UID y figure déjà, elle n'envoie plus aucune requête. Si le champ manque, la balance le crée à la première écriture.",
    "开启：当前读卡器上芯片的硬件 UID 也会以逗号分隔列表的形式写入 rfid_tag 附加字段，原绑定关系仍保留在上方所选字段中。\n\nVoron 上的 Happy Hare 仅读取 rfid_tag，且通道读卡器只能识别芯片的硬件 UID，无法读取 Bambu 料盘的 tray_uuid。若无此字段，打印机将无法识别秤已正常识别的料盘。\n\nBambu 料盘带有两枚芯片，因此有两个 UID。列表会自动追加：将料盘两面分别放上读卡器感应一次，即可在两个通道正常识别。\n\n秤会在识别到任意料盘时写入该数据，不仅限于绑定操作。若该 UID 已存在，则不会重复请求；若字段缺失，首次写入时会自动创建。" },  // STR_HW_UID_WRITE_INFO

  // ── A link that could not use the selected source ──
  { "Tag-Quelle nicht verfügbar", "Tag source unavailable", "Source de tag indisponible",
    "标签源不可用" },  // STR_TF_NOREL_TITLE
  { "Dieser Spoolman hat noch keine eigene Tag-Relation - die gibt es erst ab "
    "v0.27. Als Quelle sind aber die nativen Tags gewählt.\n\n"
    "Der Tag wurde deshalb in das Extra-Feld tag geschrieben. Die Spule wird "
    "damit gefunden, nur nicht auf dem schnellsten Weg.\n\n"
    "Dauerhaft besser: Spoolman auf v0.27 oder neuer aktualisieren. Dann zieht "
    "die Waage die Bindung beim nächsten Verknüpfen von selbst in die Relation "
    "um.",
    "This Spoolman has no tag relation of its own yet - that arrives in v0.27. "
    "The selected source is native tags all the same.\n\n"
    "The tag went into the extra field tag instead. The spool is found by it, "
    "just not by the fastest route.\n\n"
    "Better for good: update Spoolman to v0.27 or newer. The scale then moves "
    "the binding into the relation by itself, on the next link.",
    "Ce serveur Spoolman ne gère pas encore les tags nativement - cette fonction n'arrive qu'en v0.27. La source choisie est pourtant « Spoolman NFC (natif) ».\n\nLe tag a donc été enregistré dans le champ supplémentaire extra.tag. La bobine est bien retrouvée grâce à lui, mais pas par le chemin le plus rapide.\n\nSolution durable : mettre Spoolman à jour en v0.27 ou plus récent. La balance déplacera alors d'elle-même le tag vers la gestion native, lors de la prochaine liaison.",
    "当前 Spoolman 版本尚无原生标签关联功能（需 v0.27 及以上），但标签源已设为原生标签。\n\n标签已改存至 tag 附加字段中。系统仍可通过它查找料盘，只是非最优路径。\n\n建议将 Spoolman 升级至 v0.27 或更高版本，下次绑定时秤会自动将绑定关系迁移至原生关联中。" },  // STR_TF_NOREL_TEXT

  // ── The tag on the other flange ──
  { "Zweites Tag abfragen", "Ask for a second tag", "Demander un second tag",  "询问第二个标签" },  // STR_TAG2_ASK
  { "Nach dem Verknüpfen",  "Right after a link",   "Juste après une liaison", "绑定完成后" },  // STR_TAG2_ASK_SUB
  { "An: nach jedem erfolgreichen Verknüpfen fragt die Waage nach einem "
    "zweiten Tag. Spule umdrehen, Tag auflegen, fertig - es geht an dieselbe "
    "Spule wie das erste.\n\n"
    "Der Wunsch dahinter war ein zweiter Leser, einer je Gehäuseseite. Das "
    "gibt die Hardware nicht her, also macht hier ein Ablauf, was sonst ein "
    "Bauteil täte.\n\n"
    "Bei einer Bambu-Spule tragen beide Chips dieselbe tray_uuid, die zweite "
    "Chip-UID käme also ohnehin irgendwann dazu. Die Frage sagt nur, wann der "
    "Moment dafür ist. Zwei NTAGs teilen dagegen gar nichts, und ohne die "
    "Frage müsste die Spule ein zweites Mal von Hand gesucht werden.\n\n"
    "Die Zeile erscheint nur, wo die gewählte Quelle mehr als ein Tag halten "
    "kann. Ob das zweite Tag auch beschrieben wird, entscheidet weiterhin die "
    "Einstellung zum Tag-Schreiben.",
    "On: after every successful link the scale asks for a second tag. Turn the "
    "spool over, put the tag on the reader, done - it goes to the same spool "
    "as the first one.\n\n"
    "What was asked for was a second reader, one per side of the case. The "
    "hardware has one, so here a flow does what a part would have done.\n\n"
    "On a Bambu spool both chips carry the same tray uuid, so the second chip "
    "uid would turn up eventually anyway. The question only says when that "
    "moment is. Two NTAGs share nothing at all, and without it the spool has "
    "to be looked up by hand a second time.\n\n"
    "The row only appears where the selected source can hold more than one "
    "tag. Whether the second tag is written as well is still decided by the "
    "tag writing setting.",
    "Activé : après chaque liaison réussie, la balance demande un second tag. Retournez la bobine, posez le tag sur le lecteur, c'est fait - il est lié à la même bobine que le premier.\n\nLa demande d'origine était un second lecteur, un de chaque côté du boîtier. Le matériel ne le permet pas : c'est donc une étape à l'écran qui remplace ce composant.\n\nSur une bobine Bambu, les deux puces portent la même tray_uuid : l'UID de la seconde puce finirait donc par être ajouté de toute façon. La question indique seulement le bon moment pour le faire. Deux NTAG, en revanche, n'ont rien en commun : sans cette question, il faudrait rechercher la bobine à la main une seconde fois.\n\nCette ligne n'apparaît que si la source choisie peut contenir plus d'un tag. L'écriture des données sur le second tag reste décidée par le réglage « Écrire le tag après la liaison ».",
    "开启：每次成功绑定后，秤会提示读取第二个标签。翻转料盘将标签放上读卡器即可，它将关联至同一料盘。\n\n此前曾有用户在外壳两侧各装一个读卡器的需求，受限于单读卡器硬件，这里通过操作流程实现同样效果。\n\n对于 Bambu 料盘，两枚芯片共享相同的 tray_uuid，第二个芯片 UID 迟早会被自动录入，此功能只是将其提前；而两张 NTAG 互不关联，若无此提示则需手动再次查找料盘。\n\n仅当所选标签源支持多标签时才会显示此选项。第二个标签是否写入数据仍由标签写入设置决定。" },  // STR_TAG2_ASK_INFO
  { "Zweites Tag", "Second tag", "Second tag", "第二个标签" },  // STR_TAG2_TITLE
  { "Spule umdrehen und das zweite Tag auflegen",
    "Turn the spool over and place the second tag",
    "Retournez la bobine et posez le second tag",
    "翻转料盘并放置第二个标签" },  // STR_TAG2_PROMPT
  { "Schließt in %d s",      "Closes in %d s",    "Se ferme dans %d s", "%d 秒后关闭" },  // STR_TAG2_CLOSES_IN
  { "Fertig",                "Done",              "Terminer",           "完成" },  // STR_TAG2_BTN_DONE
  { "Zweites Tag verknüpft", "Second tag linked", "Second tag lié",     "已绑定第二个标签" },  // STR_TAG2_LINKED

  // ── A device built without a load cell ──
  { "Keine Waage angeschlossen", "No scale connected", "Aucune balance connectée", "未连接秤" },  // STR_NO_SCALE
  { "Waage vorhanden",           "Scale fitted",       "Balance présente",         "已装称重模块" },  // STR_SCALE_FITTED
  { "An: das Gerät hat eine Wiegezelle und verhält sich wie bisher.\n\n"
    "Aus: der ganze Waagenteil verschwindet. Der NAU7802 wird beim Start gar "
    "nicht erst gesucht, der Hauptbildschirm zeigt statt der Gewichte einen "
    "Hinweis und trägt an der Stelle von TARE nichts mehr, der Knopf "
    "\"Gewicht updaten\" wird zum Lagerort-Knopf, und Kalibrierung und "
    "Beutelgewicht verschwinden aus diesem Menü.\n\n"
    "Gedacht für ein Gerät, das nur aus Display und Leser gebaut ist: Tag "
    "auflegen, Spule sehen, Lagerort und Drucker zuordnen. Ohne diesen "
    "Schalter meldet so ein Gerät dauerhaft einen Defekt, den es nicht hat."
    "\n\n"
    "Die Umstellung braucht einen Neustart.",
    "On: the device has a load cell and behaves exactly as before.\n\n"
    "Off: the whole weighing side disappears. The NAU7802 is not even looked "
    "for at startup, the main screen carries a note instead of the weights and "
    "nothing where TARE used to be, the \"Update weight\" button becomes the "
    "location button, and calibration and bag weight leave this menu.\n\n"
    "Meant for a device built from display and reader alone: hold a tag "
    "against it, see the spool, give it a location and a printer. Without this "
    "switch such a device reports a fault it does not have, for good.\n\n"
    "Changing it needs a restart.",
    "Activé : l'appareil a un capteur de pesée et fonctionne exactement comme avant.\n\nDésactivé : toute la partie pesée disparaît. Le NAU7802 n'est même plus recherché au démarrage, l'écran principal affiche un message à la place des poids et plus rien là où se trouvait TARE, le bouton « Envoyer le poids » devient le bouton « Emplacement », et Étalonnage et Poids du sachet disparaissent de ce menu.\n\nPrévu pour un appareil composé seulement d'un écran et d'un lecteur : poser un tag, voir la bobine, lui attribuer un emplacement et une imprimante. Sans ce réglage, un tel appareil signale en permanence une panne qu'il n'a pas.\n\nLe changement nécessite un redémarrage.",
    "开启：设备配有称重传感器，工作方式与此前一致。\n\n关闭：隐藏所有称重功能。开机时不再检测 NAU7802，主界面原重量区域显示提示文字且隐藏去皮按钮，“更新重量”按钮变为“存放位置”，菜单中也会移除校准与包装袋重量选项。\n\n适用于仅由屏幕和读卡器组成的设备：刷标签查看料盘、设置位置及分配打印机。若不关闭此开关，此类设备将持续报错。\n\n更改此设置需要重启设备。" },  // STR_SCALE_FITTED_INFO
  { "Tags | Trocknung | Mehr", "Tags | Drying | More", "Tags | Séchage | Plus",
    "标签 | 烘干 | 更多" },  // STR_TILE_SCALE_SUB_OFF
  { "Waage vorhanden",         "Scale fitted",         "Balance présente",      "已安装称重模块" },  // STR_W_SCALE_FITTED
  { "Aus, wenn das Gerät nur aus Display und Leser besteht. Braucht einen "
    "Neustart.",
    "Off if the device is display and reader only. Needs a restart.",
    "À désactiver si l'appareil se limite à un écran et un lecteur. Nécessite un redémarrage.",
    "若设备仅包含屏幕与读卡器请关闭此项。更改后需重启。" },  // STR_W_SCALE_FITTED_HINT
  { "abgeschaltet", "switched off", "désactivée", "已关闭" },  // STR_W_S_SCALE_OFF

  { "Passwort", "Password", "Mot de passe", "密码" },  // STR_WEB_PASS
  { "Gesetzt - der Browser fragt danach",
    "Set - the browser asks for it",
    "Défini - le navigateur le demande",
    "已设置 - 浏览器访问需验证" },  // STR_WEB_PASS_SET
  { "Nicht gesetzt", "Not set", "Non défini", "未设置" },  // STR_WEB_PASS_UNSET
  { "Schützt die Bereiche Einstellungen und Gerät im Browser: Backend, "
    "Einstellungen, Tags, Logs und Firmware. Ohne Passwort darf jedes Gerät "
    "im Netz diese Bereiche nutzen, sobald sie eingeschaltet sind - auch "
    "Firmware flashen.\n\n"
    "4 bis 8 Ziffern. Der Browser fragt danach, der Benutzername ist egal. "
    "Leer speichern entfernt das Passwort.",
    "Protects the Settings and Device sections in the browser: backend, "
    "settings, tags, logs and firmware. Without a password any device on the "
    "network can use those sections once they are switched on - firmware "
    "upload included.\n\n"
    "4 to 8 digits. The browser asks for it, the user name does not matter. "
    "Save empty to remove the password.",
    "Protège les sections Réglages et Maintenance de l'interface web : backend, réglages, tags, journaux et firmware. Sans mot de passe, tout appareil du réseau peut utiliser ces sections dès qu'elles sont activées - y compris installer un firmware.\n\n4 à 8 chiffres. Le navigateur vous le demandera ; le nom d'utilisateur est ignoré. Validez sans rien saisir pour supprimer le mot de passe.",
    "用于保护浏览器中的“设置”与“设备”页面：后端、设置、标签、日志及固件升级。若未设密码，一旦开启对应功能，局域网内任何设备均可直接访问（包括刷写固件）。\n\n需为 4 至 8 位数字。浏览器弹窗验证时用户名任意填写即可。留空保存可清除密码。" },  // STR_WEB_PASS_INFO
  { "Web-Passwort", "Web password", "Mot de passe web", "网页密码" },  // STR_WEB_PASS_TITLE
  { "4 bis 8 Ziffern. Leer speichern entfernt das Passwort.",
    "4 to 8 digits. Save empty to remove the password.",
    "4 à 8 chiffres. Validez sans rien saisir pour supprimer le mot de passe.",
    "4 至 8 位数字。留空保存可清除密码。" },  // STR_WEB_PASS_HINT
  { "Passwort",      "Password", "Mot de passe", "密码" },  // STR_W_R_PASSWORD
  { "gesetzt",       "set",      "défini",       "已设置" },  // STR_W_S_SET
  { "nicht gesetzt", "not set",  "non défini",   "未设置" },  // STR_W_S_NOTSET
  { "Ohne Passwort kann jedes Gerät im Netz die eingeschalteten Bereiche nutzen, "
    "Firmware flashen eingeschlossen. Setzen am Gerät unter",
    "Without a password any device on the network can use the sections that "
    "are on, firmware upload included. Set one on the device under",
    "Sans mot de passe, tout appareil du réseau peut utiliser les sections activées, y compris installer un firmware. Définissez-en un sur l'écran de la balance, dans",
    "若未设置密码，局域网内任何设备均可访问已开启的功能页面（含固件上传）。请在设备端设置：" },  // STR_W_PASS_NOTE
  { "Passwort nötig: beliebiger Benutzername, das Web-Passwort der Waage.",
    "Password required: any user name, the scale's web password.",
    "Mot de passe requis : n'importe quel nom d'utilisateur, et le mot de passe web de la balance.",
    "需要密码：用户名任意，密码请填写秤的网页密码。" },  // STR_W_AUTH_NEEDED
  { "Diese Adresse gehört nicht zur Waage. Bitte über die IP-Adresse oder den "
    "Gerätenamen aufrufen.",
    "This address does not belong to the scale. Open it by IP address or by "
    "its device name.",
    "Cette adresse n'appartient pas à la balance. Ouvrez-la par son adresse IP ou par son nom d'appareil.",
    "此地址不属于该设备，请通过 IP 地址或设备名称访问。" },  // STR_W_BAD_HOST
  { "Anfrage von einer fremden Seite abgelehnt.",
    "Request from a foreign page refused.",
    "Requête venue d'une page étrangère refusée.",
    "已拒绝来自外部页面的请求。" },  // STR_W_BAD_ORIGIN
  { "%d Spulen", "%d spools", "%d bobines", "%d 个料盘" },  // STR_SPOOLS_COUNT
  { "Beide Tags gehören jetzt zu dieser Spule.",
    "Both tags now belong to this spool.",
    "Les deux tags appartiennent maintenant à cette bobine.",
    "两个标签现已均绑定至此料盘。" },  // STR_TAG2_LINKED_INFO
  { "Zweites Tag nicht verknüpft", "Second tag not linked", "Second tag non lié", "第二个标签绑定失败" },  // STR_TAG2_FAILED
  { "Spule #%d verliert das Tag.",
    "Spool #%d loses the tag.",
    "La bobine #%d perdra ce tag.",
    "料盘 #%d 将移除此标签。" },  // STR_TAGMOVE_HINT
  { "Umhängen",                "Move",           "Déplacer",             "转移" },  // STR_TAGMOVE_BTN
  { "Umhängen fehlgeschlagen", "Move failed",    "Échec du déplacement", "转移失败" },  // STR_TAGMOVE_FAILED
  { "Hängt an:",               "On spool:",      "Lié à :",              "原属料盘：" },  // STR_TAGMOVE_FROM
  { "Umhängen zu:",            "Move to:",       "Déplacer vers :",      "移至：" },  // STR_TAGMOVE_TO
  { "%d Min",                  "%d min",         "%d min",               "%d 分钟" },  // STR_MINUTES_FMT
  { "%d T.",                   "%d d",           "%d j",                 "%d天" },  // STR_DAYS_ABBR_FMT
  { "%.0f g neu",              "%.0f g new",     "%.0f g neuve",         "全新 %.0f g" },  // STR_NEW_SPOOL_WEIGHT_FMT
  { "Diff",                    "Diff",           "Écart",                "差" },  // STR_LBL_DIFF_CAP
  { "Datei wählen",            "Choose file",    "Choisir un fichier",   "选择文件" },  // STR_W_FW_CHOOSE
  { "Keine Datei gewählt",     "No file chosen", "Aucun fichier choisi", "未选择文件" },  // STR_W_FW_NOFILE
  { "Wartung (Firmware, Logs, Tags)",
    "Maintenance (firmware, logs, tags)",
    "Maintenance (firmware, journaux, tags)",
    "维护（固件、日志、标签）" },  // STR_W_R_MAINT_GATE
  { "AMS-Ansicht", "AMS view", "Vue AMS", "AMS 视图" },  // STR_AMS_BTN_VIEW
  { "%s -> Fenster für die Zuordnung öffnen?",
    "%s -> open the assignment window?",
    "%s -> ouvrir la fenêtre d'affectation ?",
    "%s -> 打开分配窗口？" },  // STR_AMSV_WINDOW_HEAD
  { "Fenster öffnen", "Open window", "Ouvrir la fenêtre", "打开窗口" },  // STR_AMSV_BTN_WINDOW
  { "Gespeichert - Test übersprungen, das Gerät ist beschäftigt",
    "Saved - test skipped, the device is busy",
    "Enregistré - test ignoré, l'appareil est occupé",
    "已保存 - 设备正忙，已跳过测试" },  // STR_W_HOST_SAVED_ONLY
  { "WLAN ändern", "Change WiFi", "Autre réseau",
    "更改 WiFi" },  // STR_BTN_WIFI_CHANGE
  { "Per Handy einrichten", "Set up by phone", "Configurer par mobile",
    "手机配网" },  // STR_BTN_WIFI_PORTAL
  { "WLAN per Handy einrichten", "Set up WiFi by phone", "Configurer le WiFi par mobile",
    "通过手机配置 WiFi" },  // STR_PORTAL_TITLE
  { "WLAN beitreten", "Join the WiFi", "Rejoignez le WiFi",
    "连接此 WiFi" },  // STR_PORTAL_STEP_JOIN
  { "Seite öffnen", "Open the page", "Ouvrez la page",
    "打开配置页面" },  // STR_PORTAL_STEP_OPEN
  { "WLAN: %s", "WiFi: %s", "WiFi : %s",
    "WiFi：%s" },  // STR_PORTAL_NET_FMT
  { "Passwort: %s", "Password: %s", "Mot de passe : %s",
    "密码：%s" },  // STR_PORTAL_PASS_FMT
  { "Öffnet sich meist von selbst", "Usually opens by itself",
    "S'ouvre le plus souvent tout seul",
    "通常会自动弹出" },  // STR_PORTAL_OPENS_ITSELF
  { "Meldet das Handy \"kein Internet\", verbunden bleiben.",
    "If the phone reports \"no internet\", stay connected.",
    "Si le téléphone signale « pas d'Internet », restez quand même connecté.",
    "若手机提示\"无网络连接\"，请保持连接。" },  // STR_PORTAL_ANDROID_HINT
  { "Warte auf Eingabe am Handy...", "Waiting for the phone...",
    "Attente de la saisie sur le téléphone...",
    "等待手机端输入..." },  // STR_PORTAL_WAITING
  { "Daten empfangen, verbinde gleich...",
    "Received, connecting in a moment...",
    "Données reçues, connexion imminente...",
    "已收到信息，即将连接..." },  // STR_PORTAL_RECEIVED
  { LV_SYMBOL_WARNING "  Das WLAN der Waage konnte nicht starten.",
    LV_SYMBOL_WARNING "  The scale's WiFi could not start.",
    LV_SYMBOL_WARNING "  Le WiFi de la balance n'a pas pu démarrer.",
    LV_SYMBOL_WARNING "  秤端 WiFi 启动失败。" },  // STR_PORTAL_START_FAILED
  { "Wähle das WLAN, mit dem sich die Waage verbinden soll.",
    "Choose the WiFi network the scale should join.",
    "Choisissez le réseau WiFi que la balance doit rejoindre.",
    "请选择秤要连接的 WiFi 网络。" },  // STR_PORTAL_PAGE_INTRO
  { "Netzwerk",     "Network",       "Réseau",           "网络" },  // STR_PORTAL_PAGE_NETWORK
  { "Bitte wählen", "Please choose", "Veuillez choisir", "请选择" },  // STR_PORTAL_PAGE_CHOOSE
  { "Oder Namen eingeben (verstecktes Netz)",
    "Or type its name (hidden network)",
    "Ou saisissez son nom (réseau masqué)",
    "或输入名称（隐藏网络）" },  // STR_PORTAL_PAGE_OTHER
  { "Passwort",  "Password", "Mot de passe", "密码" },  // STR_PORTAL_PAGE_PASS
  { "Verbinden", "Connect",  "Se connecter", "连接" },  // STR_PORTAL_PAGE_SUBMIT
  { "Die Waage verbindet sich jetzt mit %s. Das Ergebnis erscheint auf ihrem Display, dieses WLAN schaltet sich dabei ab.",
    "The scale is now connecting to %s. The result appears on its display, and this WiFi network switches off.",
    "La balance se connecte à %s. Le résultat apparaît sur son écran, et ce réseau WiFi s'éteint.",
    "秤正在连接至 %s。连接结果将显示在秤屏幕上，此热点即将关闭。" },  // STR_PORTAL_PAGE_DONE
  { "Bitte ein Netzwerk wählen oder seinen Namen eingeben (höchstens 32 Zeichen).",
    "Please choose a network or type its name (32 characters at most).",
    "Veuillez choisir un réseau ou saisir son nom (32 caractères au plus).",
    "请选择一个网络或输入其名称（最多 32 个字符）。" },  // STR_PORTAL_PAGE_ERR_SSID
  { "Das Passwort hat 8 bis 64 Zeichen, bei einem offenen Netz bleibt es leer.",
    "The password has 8 to 64 characters, or stays empty for an open network.",
    "Le mot de passe compte 8 à 64 caractères, ou reste vide pour un réseau ouvert.",
    "密码需为 8 至 64 个字符；若为开放网络请留空。" },  // STR_PORTAL_PAGE_ERR_PASS
  { "API-Key fehlt noch", "API key still missing", "Clé d'API manquante", "尚未填写 API 密钥" },  // STR_BB_KEY_MISSING
  { "API-Key abgelehnt",  "API key rejected",      "Clé d'API refusée",   "API 密钥无效" },  // STR_BB_KEY_REJECTED

  // AMS view: info mode and the detail card
  { "Info", "Info", "Infos", "提示" },  // STR_AMSV_INFO
  { "Fach antippen zeigt die Spule",
    "Tap a bay to see its spool",
    "Touchez un bac pour voir sa bobine",
    "点击槽位查看料盘" },  // STR_AMSV_INFO_HINT
  { "Der externe Halter kann nicht zugewiesen werden",
    "The external holder cannot be assigned",
    "Le support externe ne peut pas être affecté",
    "外部料架不支持分配" },  // STR_AMSV_EXT_NO_PICK
  { "%s - Fach %d", "%s - bay %d", "%s - bac %d", "%s - 槽位 %d" },  // STR_AMSD_BAY
  { "Restmenge",    "Remaining",   "Reste",       "剩余量" },  // STR_AMSD_REMAINING
  { "%s von %s",    "%s of %s",    "%s sur %s",   "%s / %s" },  // STR_AMSD_OF
  { "Kein Gewicht im Backend hinterlegt",
    "No weight stored in the backend",
    "Aucun poids enregistré dans le backend",
    "后端未记录重量" },  // STR_AMSD_NO_WEIGHT
  { "Keine Spule im Backend verknüpft",
    "No spool linked in the backend",
    "Aucune bobine liée dans le backend",
    "后端未绑定料盘" },  // STR_AMSD_NO_SPOOL
  { "Details werden geladen ...", "Loading details ...", "Chargement des détails ...",
    "正在加载详情..." },  // STR_AMSD_LOADING
  { "Details nicht abrufbar",     "Details unavailable", "Détails indisponibles",      "无法获取详情" },  // STR_AMSD_FAIL
  { "Ersatz %s",                  "Backup %s",           "Secours %s",                 "备用 %s" },  // STR_AMSD_BACKUP
  { "Trocknung von heute für\ndiese Spule speichern?",
    "Record today's drying for\nthis spool?",
    "Enregistrer le séchage du jour\npour cette bobine ?",
    "记录此料盘\n今日已完成烘干？" },  // STR_AMSD_DRIED_Q
  { "Wird gespeichert ...",     "Saving ...",    "Enregistrement ...",     "正在保存..." },  // STR_AMSD_SAVING
  { "Speichern fehlgeschlagen", "Saving failed", "Échec d'enregistrement", "保存失败" },  // STR_AMSD_WRITE_FAIL

  // The caption the main screen and More Info used to spell out as a literal.
  { "Material", "Material", "Matériau", "材质" },  // STR_LBL_MATERIAL

  // More captions that used to be literals, for the same reason.
  { "Status",             "Status",             "Statut",                      "状态" },  // STR_LBL_STATUS
  { "Status",             "Status",             "État",                        "状态" },  // STR_WIFI_ROW_STATUS
  { "Gateway",            "Gateway",            "Passerelle",                  "网关" },  // STR_WIFI_ROW_GATEWAY
  { "Name",               "Name",               "Nom",                         "名称" },  // STR_IP_BAR_NAME
  { "%s Server",          "%s Server",          "Serveur %s",                  "%s 服务器" },  // STR_SERVER_TITLE
  { "%s UUID",            "%s UUID",            "UUID %s",                     "%s UUID" },  // STR_BACKEND_UUID
  { "Language / Sprache", "Language / Sprache", "Langue / Language / Sprache",
    "Language / 语言" },  // STR_LANG_SCREEN_TITLE
  { "DEL",                "DEL",                "Effacer",                     "删除" },  // STR_KEY_DEL

  // AMS detail card: drying for the whole unit, and the material conflict hint
  { "Trocknung von heute speichern?",
    "Record today's drying?",
    "Noter le séchage du jour ?",
    "记录今日已完成烘干？" },  // STR_AMSD_DRIED_Q_ALL
  { "Alle %d Spulen in %s", "All %d spools in %s", "%d bobines (%s)", "全部 %d 个料盘 (%s)" },  // STR_AMSD_DRIED_ALL
  { "Nur diese Spule",      "This spool only",     "Celle-ci seule",  "仅此料盘" },  // STR_AMSD_DRIED_ONE
  { "%d Spulen werden gespeichert ...",
    "Saving %d spools ...",
    "Sauvegarde de %d bobines ...",
    "正在保存 %d 个料盘..." },  // STR_AMSD_BATCH_RUNNING
  { "%d von %d gespeichert", "%d of %d saved", "%d sur %d sauvées", "已保存 %d / %d" },  // STR_AMSD_BATCH_DONE
  { "Trocknet %d min",       "Drying %d min",  "Séchage %d min",    "烘干中 %d 分钟" },  // STR_AMSV_DRYING_MIN
  { "Trocknet",              "Drying",         "Séchage",           "烘干中" },  // STR_AMSV_DRYING
  { "Drucker meldet %s - Zuordnung im Backend prüfen",
    "Printer reports %s - check the assignment in the backend",
    "Imprimante : %s - vérifier l'affectation",
    "打印机报告为 %s - 请在后端检查绑定" },  // STR_AMSD_TYPE_CONFLICT
  { "Snapmaker-Tags lesen", "Read Snapmaker tags", "Lire les tags Snapmaker", "读取 Snapmaker 标签" },  // STR_W_SNAPMAKER
  { "Versucht bei einem 4-Byte-Tag, der kein Bambu-Tag ist, die Snapmaker-Schlüssel und liest Material und Farbe vom Tag. Kostet jeden anderen 4-Byte-Tag etwa eine halbe Sekunde beim Auflegen. Aus lassen, wenn keine Snapmaker-Spulen im Haus sind.",
    "Tries Snapmaker's keys on a 4 byte tag that is not a Bambu tag and reads material and colour off the tag. Costs every other 4 byte tag about half a second when it is put down. Leave it off if there are no Snapmaker spools around.",
    "Essaie les clés Snapmaker sur un tag de 4 octets qui n'est pas un tag Bambu, et lit le matériau et la couleur sur le tag. Chaque autre tag de 4 octets met alors environ une demi-seconde de plus à être reconnu. À laisser désactivé s'il n'y a pas de bobines Snapmaker.",
    "对于非 Bambu 的 4 字节标签，尝试使用 Snapmaker 密钥读取材质和颜色。这会使其他 4 字节标签在放置时增加约半秒的识别耗时。若无 Snapmaker 料盘，建议关闭。" },  // STR_W_SNAPMAKER_HINT
  { "Einmalig kurz per USB aktualisieren",
    "A quick one-time update over USB",
    "Mise à jour USB rapide, une fois",
    "需通过 USB 进行一次快速更新" },  // STR_PART_HINT_TITLE
  { "Für künftige Updates mit neuen Funktionen muss der Speicherbereich für die Firmware vergrößert werden. Das geht nur einmalig per USB-Kabel über den Web-Flasher: etwa 2 Minuten, alle Einstellungen bleiben erhalten. Danach kommen Updates wieder wie gewohnt drahtlos.",
    "For future updates with new features, the storage area for the firmware has to be enlarged. That only works once over a USB cable with the web flasher: about 2 minutes, every setting is kept. After that, updates arrive over the air as usual.",
    "Pour les futures mises à jour, la zone mémoire du firmware doit être agrandie. Cela ne se fait qu'une fois, par câble USB avec le Web Flasher : environ 2 minutes, tous les réglages sont conservés. Ensuite, les mises à jour arrivent sans fil comme avant.",
    "为支持未来的新功能更新，需要扩大固件存储分区。此操作仅需通过 USB 数据线使用网页刷机工具执行一次：耗时约 2 分钟，所有设置均会保留。此后即可照常进行 OTA 无线更新。" },  // STR_PART_HINT_TEXT
  { "Layout",   "Layout",   "Partitionnement", "分区布局" },  // STR_W_R_LAYOUT
  { "aktuell",  "current",  "actuel",          "最新" },  // STR_W_S_LAYOUT_NEW
  { "veraltet", "outdated", "obsolète",        "旧版" },  // STR_W_S_LAYOUT_OLD
  { "Einmal per USB über den Web Flasher neu flashen bringt das aktuelle Layout. Die Einstellungen bleiben dabei erhalten.",
    "One flash over USB with the web flasher brings the current layout. Your settings are kept.",
    "Un flash par USB avec le Web Flasher apporte le partitionnement actuel. Les réglages sont conservés.",
    "通过 USB 使用网页刷机工具重新刷写一次即可升级至最新布局，您的所有设置均会保留。" },  // STR_W_S_LAYOUT_OLD_HINT
  { "Firmware",     "Firmware",    "Firmware",     "固件" },  // STR_W_R_FIRMWARE
  { "%s von %s MB", "%s of %s MB", "%s sur %s Mo", "%s / %s MB" },  // STR_W_S_MB_OF
  { "Datenbereich", "Data area",
    "Zone de données",
    "数据区" },  // STR_W_R_DATA_AREA
  { "%s MB, noch nicht genutzt", "%s MB, not used yet",
    "%s Mo, pas encore utilisée",
    "%s MB，尚未使用" },  // STR_W_S_DATA_UNUSED
  { "nicht vorhanden", "not present", "absente", "无" },  // STR_W_S_NONE
  { "Absturzspeicher", "Crash dump",
    "Rapport de plantage",
    "崩溃转储" },  // STR_W_R_COREDUMP
  { "Nicht verknüpft: keine Verbindung", "Not linked: no connection",
    "Non lié : pas de connexion",
    "未绑定：无连接" },  // STR_LINK_NO_CONNECTION
  { "Unlink fehlgeschlagen: keine Verbindung", "Not unlinked: no connection",
    "Non dissocié : pas de connexion",
    "未解绑：无连接" },  // STR_UNLINK_NO_CONNECTION
  { "Keine Verbindung", "No connection",
    "Pas de connexion",
    "无连接" },  // STR_NO_CONNECTION
  { "Keine Verbindung zu Spoolman", "No connection to Spoolman",
    "Pas de connexion à Spoolman",
    "未连接到 Spoolman" },  // STR_NO_CONNECTION_TO
  { "Keine Verbindung zum Server", "No connection to the server",
    "Pas de connexion au serveur",
    "无法连接到服务器" },  // STR_SERVER_DOWN_TITLE
  { "Der Server hat nicht geantwortet. Prüfe, ob er läuft und ob die Waage im WLAN ist, und versuche es dann noch einmal.",
    "The server did not answer. Check that it is running and that the scale is on the WiFi, then try again.",
    "Le serveur n'a pas répondu. Vérifiez qu'il fonctionne et que la balance est connectée au WiFi, puis réessayez.",
    "服务器未响应。请检查服务器是否正在运行以及秤是否已连接 WiFi，然后重试。" },  // STR_SERVER_DOWN_TEXT
  { "Protokoll schreiben",
    "Write the log",
    "Écrire le journal",
    "日志保存位置" },  // STR_W_R_LOGDEST
  { "Aus",
    "Off",
    "Désactivé",
    "关闭" },  // STR_W_S_DEST_OFF
  { "SD-Karte",
    "SD card",
    "Carte SD",
    "SD 卡" },  // STR_W_S_DEST_SD
  { "Intern",
    "Internal",
    "Interne",
    "内置存储" },  // STR_W_S_DEST_INT
  { "Umfang",
    "Scope",
    "Niveau",
    "日志级别" },  // STR_W_R_LOGLVL
  { "Knapp",
    "Minimal",
    "Minimal",
    "精简" },  // STR_W_S_LVL_MIN
  { "Normal",
    "Normal",
    "Normal",
    "正常" },  // STR_W_S_LVL_NORM
  { "Ausführlich",
    "Verbose",
    "Détaillé",
    "详细" },  // STR_W_S_LVL_VERB
  { "Interner Speicher",
    "Internal storage",
    "Mémoire interne",
    "内置存储" },  // STR_W_LOG_INTERNAL
  { "{a} von {b} Zeilen",
    "{a} of {b} lines",
    "{a} sur {b} lignes",
    "第 {a} 行，共 {b} 行" },  // STR_W_LOG_LINES_OF
  { "Alle",
    "All",
    "Tous",
    "全部" },  // STR_W_LOG_SRC_ALL
  { "Nicht verfügbar",
    "Not available",
    "Non disponible",
    "不可用" },  // STR_W_LOG_INT_NONE
  { "Der interne Speicher fasst 4.096 Zeilen und überschreibt die ältesten. Das sind etwa zwei Tage im Umfang \"Normal\" und mehrere Stunden im Umfang \"Ausführlich\".",
    "The internal storage holds 4,096 lines and overwrites the oldest. That is about two days at normal scope and several hours at verbose.",
    "La mémoire interne contient 4 096 lignes et écrase les plus anciennes. Cela fait environ deux jours au niveau « Normal » et plusieurs heures au niveau « Détaillé ».",
    "内置存储最多保存 4,096 行日志，超出后将覆盖最早的记录。在“正常”级别下约可保存两天，在“详细”级别下约可保存数小时。" },  // STR_W_LOG_INT_NOTE
  { "Spule hat sich geändert, Liste neu geladen",
    "That spool changed, the list was reloaded",
    "La bobine a changé, liste rechargée",
    "料盘已变更，列表已刷新" },  // STR_LIST_SPOOL_CHANGED
  { "Stand: %02d:%02d (vor %s min)",
    "As of %02d:%02d (%s min ago)",
    "À %02d:%02d (il y a %s min)",
    "更新于 %02d:%02d (%s 分钟前)" },  // STR_LIST_AS_OF
  { "Neu laden",
    "Reload",
    "Recharger",
    "刷新" },  // STR_LIST_RELOAD
  { "Tag wird beschrieben",
    "Writing the tag",
    "Écriture du tag",
    "正在写入标签" },  // STR_TW_BUSY_WRITE
  { "Tag wird gelöscht",
    "Erasing the tag",
    "Effacement du tag",
    "正在擦除标签" },  // STR_TW_BUSY_ERASE
  { "Spule bitte liegen lassen, bis die Bestätigung kommt.",
    "Please leave the spool where it is until this is confirmed.",
    "Laissez la bobine en place jusqu'à la confirmation.",
    "请勿移动料盘，直至操作确认完成。" },  // STR_TW_BUSY_HINT

  // Tag page in the browser: a MIFARE tag, and the spool the scale shows
  { "Nur lesbar, und nichts darauf, was die Waage kennt.",
    "Read-only, and nothing on it this scale knows.",
    "Lecture seule, sans contenu connu de cette balance.",
    "只读标签，且未包含此秤可识别的数据。" },  // STR_W_TAG_NOREC
  { "Tray-UUID",           "Tray UUID",          "Tray UUID",             "托盘 UUID" },  // STR_W_TAG_TRAY
  { "Spule auf der Waage", "Spool on the scale", "Bobine sur la balance", "秤盘上的料盘" },  // STR_W_TAG_ONSCALE
  { "Die Waage zeigt gerade keine Spule.",
    "The scale shows no spool right now.",
    "La balance n'affiche aucune bobine pour le moment.",
    "当前秤上未检测到料盘。" },  // STR_W_TAG_NOSPOOL

  // Tag view on the device, from the NFC chip in the header
  { "NFC-Tag",   "NFC tag", "Tag NFC", "NFC标签" },  // STR_TV_TITLE
  { "UID",       "UID",     "UID",     "UID" },  // STR_TV_UID
  { "Chip",      "Chip",    "Puce",    "芯片" },  // STR_TV_CHIP
  { "leer",      "blank",   "vierge",  "空白" },  // STR_TV_FMT_BLANK
  { "unbekannt", "unknown", "inconnu", "未知" },  // STR_TV_FMT_UNKNOWN
  { "keins",     "none",    "aucun",   "无" },  // STR_TV_FMT_NONE
  { "Auf dem Tag steht nichts. Er kann beschrieben werden.",
    "There is nothing on the tag. It can be written.",
    "Le tag est vide. Il peut être écrit.",
    "标签为空，可写入数据。" },  // STR_TV_BLANK_NOTE
  { "Kein Tag auf dem Leser. Leg einen auf, er erscheint hier sofort.",
    "No tag on the reader. Put one down and it shows up here right away.",
    "Aucun tag sur le lecteur. Posez-en un, il s'affiche ici aussitôt.",
    "未检测到标签。将标签靠近读卡器即可立即显示。" },  // STR_TV_PLACE
  { "Der NFC-Leser antwortet gerade nicht. Tags werden erst wieder gelesen, wenn er zurück ist.",
    "The NFC reader is not answering right now. Tags are read again once it is back.",
    "Le lecteur NFC ne répond pas. Les tags seront relus dès son retour.",
    "NFC 读卡器当前无响应，恢复后将重新开始读取标签。" },  // STR_TV_READER_DOWN
  { "Spule #%d schreiben", "Write spool #%d",     "Écrire bobine #%d", "写入料盘 #%d" },  // STR_TV_WRITE
  { "Keine Spule erkannt", "No spool recognised", "Aucune bobine",     "未识别到料盘" },  // STR_TV_NOSPOOL
  { "Tag zu klein",        "Tag too small",       "Tag trop petit",    "标签容量过小" },  // STR_TV_TOOSMALL
  { "Tag löschen?",        "Erase the tag?",      "Effacer le tag ?",  "擦除标签？" },  // STR_TV_ERASE_TITLE
  { "Was darauf steht, geht verloren. Eine Verknüpfung mit einer Spule bleibt bestehen.",
    "Whatever is on it is lost. A link to a spool stays as it is.",
    "Son contenu sera perdu. Une liaison avec une bobine reste en place.",
    "标签内数据将被清空，与料盘的绑定关系保持不变。" },  // STR_TV_ERASE_HINT

  // Tag page in the browser: linking the tag on the reader without writing it
  { "Nur verknüpfen", "Link only", "Lier seulement", "仅绑定" },  // STR_W_TAG_LINKONLY
  { "Dieser Tag ist nur lesbar. Verknüpfen geht trotzdem.",
    "This tag can only be read. It can still be linked.",
    "Ce tag est en lecture seule. On peut quand même le lier.",
    "此标签为只读，但仍可进行绑定。" },  // STR_W_TAG_RO_LINK
  { "Spule #%d ist schon mit Tag %s verknüpft. Stattdessen diesen Tag verknüpfen? Der bisherige verliert die Verknüpfung.",
    "Spool #%d is already linked to tag %s. Link this tag instead? The old one loses its link.",
    "La bobine #%d est déjà liée au tag %s. Lier ce tag à la place ? L'ancien perd sa liaison.",
    "料盘 #%d 已绑定标签 %s。是否改绑此标签？原标签将解除绑定。" },  // STR_W_TL_ASK_REPLACE
  { "Spule #%d ist schon mit Tag %s verknüpft. Diesen Tag dazu verknüpfen? Beide führen danach zur Spule.",
    "Spool #%d is already linked to tag %s. Link this tag as well? Both lead to the spool afterwards.",
    "La bobine #%d est déjà liée au tag %s. Lier aussi ce tag ? Les deux mèneront ensuite à la bobine.",
    "料盘 #%d 已绑定标签 %s。是否同时绑定此标签？绑定后两个标签均指向该料盘。" },  // STR_W_TL_ASK_ADD
  { "Nicht angenommen: es läuft schon eine Verknüpfung, oder Spule oder Tag fehlen.",
    "Not accepted: a link is already running, or the spool or the tag is missing.",
    "Refusé : une liaison est déjà en cours, ou la bobine ou le tag manque.",
    "操作被拒绝：正在进行绑定，或缺少料盘/标签。" },  // STR_W_TL_REFUSED
  { "Verknüpfe mit Spule #%d ...", "Linking to spool #%d ...",
    "Liaison avec la bobine #%d ...",
    "正在绑定至料盘 #%d..." },  // STR_W_TL_BUSY
  { "Tag mit Spule #%d verknüpft.", "Tag linked to spool #%d.",
    "Tag lié à la bobine #%d.",
    "标签已绑定至料盘 #%d。" },  // STR_W_TL_OK
  { "Der Tag ist schon mit Spule #%d verknüpft.", "The tag is already linked to spool #%d.",
    "Le tag est déjà lié à la bobine #%d.",
    "此标签已绑定至料盘 #%d。" },  // STR_W_TL_ALREADY
  { "Der Tag gehört zu Spule #%d. Dort zuerst die Verknüpfung lösen.",
    "The tag belongs to spool #%d. Unlink it there first.",
    "Le tag appartient à la bobine #%d. Dissociez-le d'abord de cette bobine.",
    "此标签属于料盘 #%d，请先在该料盘中解绑。" },  // STR_W_TL_HELD
  { "Auf dem Leser liegt inzwischen ein anderer Tag. Nichts verknüpft.",
    "A different tag is on the reader now. Nothing was linked.",
    "Un autre tag est maintenant sur le lecteur. Rien n'a été lié.",
    "读卡器上的标签已更换，未执行绑定。" },  // STR_W_TL_CHANGED
  { "Der Server hat die Verknüpfung abgelehnt.", "The server refused the link.",
    "Le serveur a refusé la liaison.",
    "服务器拒绝了绑定请求。" },  // STR_W_TL_FAILED
  { "%s | Vorlage #%d", "%s | template #%d",
    "%s | modèle #%d",
    "%s | 模板 #%d" },  // STR_COPY_CARD_TEMPLATE
  { "Neue Spule: %.0f g netto | leer %.0f g", "New spool: %.0f g net | empty %.0f g",
    "Bobine neuve : %.0f g net | vide %.0f g",
    "新料盘：净重 %.0f g | 空盘 %.0f g" },  // STR_COPY_CARD_WEIGHT
  { "Anlegen", "Create",
    "Créer",
    "创建" },  // STR_COPY_CARD_CREATE

  // Bluetooth: the Connection tile, the screen behind it, the device scan
  { "Bluetooth",        "Bluetooth",     "Bluetooth", "蓝牙" },  // STR_BT_TITLE
  { "Bluetooth nutzen", "Use Bluetooth", "Bluetooth", "启用蓝牙" },  // STR_BT_SWITCH
  { "Funk nur bei Bedarf an", "Radio only on when needed",
    "Radio active au besoin",
    "仅在需要时开启射频" },  // STR_BT_SWITCH_SUB
  { "Bluetooth-Geräte suchen...", "Scanning for Bluetooth devices...", "Recherche Bluetooth...",
    "正在搜索蓝牙设备..." },  // STR_BT_SCANNING
  { "Keine Geräte gefunden", "No devices found",
    "Aucun appareil trouvé",
    "未发现设备" },  // STR_BT_NONE_FOUND
  { "(ohne Namen)", "(no name)", "(sans nom)", "(未命名)" },  // STR_BT_UNNAMED
  { "Bluetooth konnte nicht gestartet werden. Zu wenig freier Speicher, siehe Log.",
    "Bluetooth could not be started. Not enough free memory, see the log.",
    "Bluetooth n'a pas démarré. Mémoire insuffisante, voir le journal.",
    "蓝牙启动失败：可用内存不足，请查看日志。" },  // STR_BT_INIT_FAILED
  { "Aus: kein Bluetooth, nichts läuft im Hintergrund. An: Funktionen wie die Gerätesuche starten den Funk bei Bedarf und geben ihn danach wieder frei. Die Suche zeigt, was in Reichweite ist. Verbunden wird nur zum Drucken, mit dem eingerichteten Drucker. Nach dem Einschalten startet die Waage einmal neu.",
    "Off: no Bluetooth, nothing runs in the background. On: features such as the device scan start the radio when needed and release it afterwards. The scan lists what is in range. A connection is only made to print, to the printer that is set up. After switching it on, the scale restarts once.",
    "Désactivé : pas de Bluetooth, rien en arrière-plan. Activé : la recherche d'appareils et les autres fonctions allument la radio au besoin, puis la libèrent. La recherche montre ce qui est à portée. Une connexion n'est établie que pour imprimer, avec l'imprimante configurée. Après l'activation, la balance redémarre une fois.",
    "关闭：禁用蓝牙，后台无运行。开启：设备扫描等功能仅在需要时开启射频，使用后自动释放。扫描将列出范围内的设备，仅在打印时连接已配置的打印机。开启后秤将重启一次。" },  // STR_BT_HELP
  { "Geräte",                "Devices",          "Appareils",          "设备" },  // STR_BT_DEVICES
  { "Noch nicht gesucht",    "Not searched yet", "Aucune recherche",   "尚未搜索" },  // STR_BT_DEVICES_NONE_YET
  { "%d in Reichweite",      "%d in range",      "%d à portée",        "范围内 %d 个" },  // STR_BT_DEVICES_FMT
  { "stark",                 "strong",           "fort",               "强" },  // STR_BT_SIG_STRONG
  { "mittel",                "medium",           "moyen",              "中" },  // STR_BT_SIG_MEDIUM
  { "schwach",               "weak",             "faible",             "弱" },  // STR_BT_SIG_WEAK
  { "Adresse",               "Address",          "Adresse",            "地址" },  // STR_BT_CARD_ADDRESS
  { "Signal",                "Signal",           "Signal",             "信号" },  // STR_BT_CARD_SIGNAL
  { "Schließen",             "Close",            "Fermer",             "关闭" },  // STR_BT_CLOSE
  { "Als Drucker",           "As printer",       "Imprimante",         "设为打印机" },  // STR_BT_CARD_USE_PRINTER
  { "Eingestellter Drucker", "The printer",      "Imprimante choisie", "当前打印机" },  // STR_BT_CARD_IS_PRINTER
  { "Entfernen",             "Remove",           "Retirer",            "移除" },  // STR_BT_CARD_FORGET_PRINTER

  // The label printer: its screen, its rows, what a print came back with
  { "Drucker", "Printer",
    "Imprimante",
    "打印机" },  // STR_PRN_TITLE
  { "Kein Drucker", "No printer",
    "Aucune imprimante",
    "无打印机" },  // STR_PRN_NONE
  { "Gerät", "Device",
    "Appareil",
    "设备" },  // STR_PRN_DEVICE
  { "Keines gewählt, auf der Gerätekarte wählen", "None picked, pick one on the device card",
    "Aucun, à choisir dans la liste",
    "未选择，请在设备卡片上选择" },  // STR_PRN_DEVICE_NONE
  { "Modell", "Model",
    "Modèle",
    "型号" },  // STR_PRN_MODEL
  { "(experimentell, ungetestet)", "(experimental, untested)",
    "(expérimental, non testé)",
    "（实验性，未经测试）" },  // STR_PRN_EXPERIMENTAL
  { "Etikett", "Label stock",
    "Étiquette",
    "标签规格" },  // STR_PRN_MEDIA
  { "%u x %u mm", "%u x %u mm",
    "%u x %u mm",
    "%u x %u mm" },  // STR_PRN_MEDIA_FMT
  { "Testdruck", "Test print",
    "Test d'impression",
    "测试打印" },  // STR_PRN_TEST
  { "Rahmen, Name und QR-Code auf dem eingelegten Etikett", "Frame, name and QR code on the loaded label",
    "Cadre, nom et code QR sur l'étiquette chargée",
    "在装入的标签上打印边框、名称与 QR 码" },  // STR_PRN_TEST_SUB
  { "Drucker entfernen", "Remove printer",
    "Retirer l'imprimante",
    "移除打印机" },  // STR_PRN_FORGET
  { "Das Etikett wurde an den Drucker übertragen.", "The label was sent to the printer.",
    "L'étiquette a été envoyée à l'imprimante.",
    "标签已发送至打印机。" },  // STR_PRN_OK
  { "Kein Drucker gewählt.", "No printer picked.",
    "Aucune imprimante.",
    "未选择打印机。" },  // STR_PRN_ERR_NO_PRINTER
  { "Das Etikett konnte nicht gerendert werden.", "The label could not be rendered.",
    "Étiquette non générée.",
    "无法渲染标签。" },  // STR_PRN_ERR_RASTER
  { "Das Etikett ist breiter als der Druckkopf.", "The label is wider than the print head.",
    "Étiquette plus large que la tête.",
    "标签宽度超出打印头范围。" },  // STR_PRN_ERR_TOO_WIDE
  { "Das Etikett passt nicht zum eingelegten Format.", "The label does not match the loaded stock.",
    "Étiquette et format chargé différents.",
    "标签与装入的耗材规格不符。" },  // STR_PRN_ERR_MEDIA
  { "Bluetooth ist aus.", "Bluetooth is off.",
    "Bluetooth inactif.",
    "蓝牙未开启。" },  // STR_PRN_ERR_BLE_OFF
  { "Der Drucker antwortet nicht. Ist er eingeschaltet und in Reichweite?",
    "The printer does not answer. Is it on and in range?",
    "L'imprimante ne répond pas. Allumée et à portée ?",
    "打印机无响应，请检查是否开机并在范围内。" },  // STR_PRN_ERR_CONNECT
  { "Das Gerät ist kein Phomemo-Drucker.", "The device is not a Phomemo printer.",
    "Pas une imprimante Phomemo.",
    "该设备不是 Phomemo 打印机。" },  // STR_PRN_ERR_NOT_PRINTER
  { "Die Verbindung ließ sich nicht trennen. Bitte neu starten.",
    "The link would not close. Please restart.",
    "Connexion bloquée. Redémarrez.",
    "连接无法关闭，请重启设备。" },  // STR_PRN_ERR_STUCK
  { "Die Übertragung ist abgebrochen.", "The transfer was cut off.", "Transfert interrompu.",
    "数据传输已中断。" },  // STR_PRN_ERR_WRITE
  { "Der Drucker wird auf der Gerätekarte gewählt. Modell und Etikett passen den Druck an den Druckkopf und das eingelegte Etikett an; der Testdruck zeigt, ob beides stimmt. Beim Drucken steht die Waage einige Sekunden.",
    "The printer is picked on the device card. Model and label stock fit the print to the head and the loaded label; the test print shows whether both are right. The scale pauses for a few seconds while printing.",
    "L'imprimante se choisit parmi les appareils. Modèle et étiquette adaptent l'impression à la tête et au support ; le test montre si les deux sont bons. La balance s'arrête quelques secondes pendant l'impression.",
    "请在设备卡片上选择打印机。型号与标签规格需匹配打印头和已装入的标签；测试打印可验证两者是否正确。打印期间称重台会暂停数秒。" },  // STR_PRN_HELP

  // The printer page in the browser
  { "Drucker", "Printer", "Imprimante", "打印机" },  // STR_W_NAV_PRINTER
  { "Nur bei Bedarf an: der Funk läuft, während ein Gerät ihn braucht, und wird danach freigegeben. Nach dem Einschalten braucht die Waage einmal einen Neustart.",
    "Only when needed: the radio runs while a device needs it and is released afterwards. After switching it on, the scale needs one restart.",
    "Seulement au besoin : la radio tourne tant qu'un appareil l'utilise, puis est libérée. Après l'activation, la balance a besoin d'un redémarrage.",
    "按需启用：仅在设备需要时开启蓝牙射频，使用后自动释放。开启此选项后需重启一次称重台。" },  // STR_W_P_BLE_HINT
  { "Weitere Modelle kommen mit Rückmeldungen aus der Community.",
    "More models come with feedback from the community.",
    "D'autres modèles viendront avec les retours de la communauté.",
    "更多支持型号将根据社区反馈陆续添加。" },  // STR_W_P_SUPPORTED_HINT
  { "Geräte in Reichweite", "Devices in range", "Appareils à portée", "范围内的设备" },  // STR_W_P_DEVICES
  { "Geräte suchen",        "Scan for devices", "Rechercher",         "搜索设备" },  // STR_BT_SCAN_WEB
  { "Die Suche läuft auf der Waage und dauert etwa 5 Sekunden; solange steht sie.",
    "The scan runs on the scale and takes about 5 seconds; the scale pauses meanwhile.",
    "La recherche tourne sur la balance et dure environ 5 secondes ; la balance est en pause pendant ce temps.",
    "搜索将在称重台上运行约 5 秒，期间称重功能会暂时暂停。" },  // STR_W_P_SCAN_HINT
  { "Breite quer zum Druckkopf mal Länge in Laufrichtung, wie auf der Rolle angegeben.",
    "Width across the head by length along the feed, as printed on the roll.",
    "Largeur (le long de la tête d'impression) × longueur (dans le sens du défilement), comme indiqué sur le rouleau.",
    "打印头横向宽度 × 走纸方向长度（如标签卷所标示）。" },  // STR_W_P_MEDIA_HINT
  { "Druckt Rahmen, Name und QR-Code auf das eingelegte Etikett. Das Ergebnis erscheint auch auf der Waage.",
    "Prints a frame, the name and a QR code on the loaded label. The verdict also shows on the scale.",
    "Imprime un cadre, le nom et un code QR sur l'étiquette chargée. Le résultat s'affiche aussi sur la balance.",
    "在当前装入的标签上打印边框、名称及 QR 码，打印结果也会同步显示在称重台屏幕上。" },  // STR_W_P_TEST_HINT
  { "Letzter Testdruck",      "Last test print",     "Dernier test",          "上次测试打印" },  // STR_W_P_LAST_TEST
  { "An die Waage übergeben", "Handed to the scale", "Transmis à la balance", "已交由称重台处理" },  // STR_W_P_QUEUED
  { "Etikett drucken",        "Print label",         "Imprimer",              "打印标签" },  // STR_PRN_LABEL_PRINT
  { "Keine bekannte Spule aufgelegt.", "No known spool on the pad.",
    "Aucune bobine connue posée.",
    "秤盘上无已识别的料盘。" },  // STR_PRN_ERR_NO_SPOOL
  // The captions on a printed label, short: the lines are 16 px on a 40 mm roll
  { "Farbe", "Colour", "Couleur", "颜色" },  // STR_LBL_L_COLOR
  { "Etikett wird erstellt...",
    "Preparing the label...",
    "Préparation...",
    "正在生成标签..." },  // STR_PRN_PH_RENDER
  { "Drucker wird gesucht...",
    "Looking for the printer...",
    "Recherche en cours...",
    "正在搜索打印机..." },  // STR_PRN_PH_FIND
  { "Verbinde mit dem Drucker...",
    "Connecting to the printer...",
    "Connexion à l'imprimante...",
    "正在连接打印机..." },  // STR_PRN_PH_CONNECT
  { "Etikett wird gesendet",
    "Sending the label",
    "Envoi de l'étiquette",
    "正在发送标签" },  // STR_PRN_PH_SEND
  { "Drucker druckt...",
    "The printer is printing...",
    "Impression en cours...",
    "打印机正在打印..." },  // STR_PRN_PH_AWAIT
  { "Gedruckt",
    "Printed",
    "Imprimé",
    "打印完成" },  // STR_PRN_DONE_TITLE
  { "Der Drucker hat den Druck bestätigt.",
    "The printer confirmed the print.",
    "L'imprimante a confirmé.",
    "打印机已确认完成打印。" },  // STR_PRN_DONE_MSG
  { "Gesendet",
    "Sent",
    "Envoyé",
    "已发送" },  // STR_PRN_UNCONF_TITLE
  { "Der Drucker hat den Druck nicht bestätigt. Papier und Deckel prüfen.",
    "The printer did not confirm the print. Check the paper and the lid.",
    "L'imprimante n'a pas confirmé. Vérifiez papier et capot.",
    "打印机未确认打印，请检查标签纸和上盖。" },  // STR_PRN_UNCONF_MSG
  { "Nicht gedruckt",
    "Not printed",
    "Non imprimé",
    "打印失败" },  // STR_PRN_FAIL_TITLE
  { "Nur Geräte mit Namen. Fehlt deins? Näher an die Waage bringen und neu suchen.",
    "Only devices with a name. Yours is missing? Bring it closer to the scale and scan again.",
    "Seulement les appareils nommés. Le vôtre manque ? Rapprochez-le et relancez.",
    "仅显示有名称的设备。未找到？请靠近秤后重新扫描。" },  // STR_BT_FILTER_NOTE
  { "Alle anzeigen (+%d ohne Namen)",
    "Show all (+%d without a name)",
    "Tout afficher (+%d sans nom)",
    "显示全部（+%d 个无名称）" },  // STR_BT_SHOW_ALL_FMT
  { "Nur Geräte mit Namen",
    "Only devices with a name",
    "Appareils nommés seulement",
    "仅显示有名称的设备" },  // STR_BT_SHOW_NAMED
  { "Anleitung",
    "Manual",
    "Manuel",
    "使用手册" },  // STR_QR_DOCS_TITLE
  { "Einrichtung, Funktionen, häufige Fragen",
    "Setup, features, common questions",
    "Installation, fonctions, FAQ",
    "设置、功能与常见问题" },  // STR_QR_DOCS_DESC
  { "Auf der Waage",
    "On the scale",
    "Sur la balance",
    "秤上料盘" },  // STR_W_C_ONSCALE
  { "NFC-Tag",
    "NFC tag",
    "Tag NFC",
    "NFC 标签" },  // STR_W_TAG_BADGE_TAG
  { "Vorschau",
    "Preview",
    "Aperçu",
    "预览" },  // STR_W_TAG_PREVIEW
  { "Kein Eintrag in %s für diesen Tag.",
    "No record in %s for this tag.",
    "Aucune fiche dans %s pour ce tag.",
    "%s 中无此标签的记录。" },  // STR_W_TAG_NOTLINKED
  { "Spulen-ID",
    "Spool ID",
    "ID bobine",
    "料盘 ID" },  // STR_W_TAG_SPOOLID
  { "Protokoll",
    "Protocol",
    "Protocole",
    "协议" },  // STR_W_TAG_PROTO
  { "Rohdaten",
    "Raw data",
    "Données brutes",
    "原始数据" },  // STR_W_TAG_RAW
  { "Rohdaten des Tags",
    "Raw tag data",
    "Données brutes du tag",
    "标签原始数据" },  // STR_W_TAG_RAW_TITLE
  { "Kopieren",
    "Copy",
    "Copier",
    "复制" },  // STR_W_COPY
  { "Kopiert",
    "Copied",
    "Copié",
    "已复制" },  // STR_W_COPIED
  { "Schreibe...",
    "Writing...",
    "Écriture...",
    "正在写入..." },  // STR_W_TW_BUSY_BTN
  { "Tag auf dem Leser liegen lassen",
    "Keep the tag on the reader",
    "Laissez le tag sur le lecteur",
    "请保持标签贴近读卡器" },  // STR_W_TW_KEEP
  { "Tag auflegen und noch einmal versuchen",
    "Put the tag on and try again",
    "Posez le tag et réessayez",
    "请放上标签后重试" },  // STR_W_TW_RETRY
  { "Zweiten Tag für diese Spule?",
    "A second tag for this spool?",
    "Un second tag pour cette bobine ?",
    "要为此料盘写入第二个标签吗？" },  // STR_W_T2_OFFER
  { "Etwa für den Halter oder die Box. Beide Tags finden dieselbe Spule.",
    "For the holder or the box, say. Both tags find the same spool.",
    "Par exemple pour le support ou la boîte. Les deux tags renvoient à la même bobine.",
    "例如贴在支架或密封盒上，两个标签均可识别同一料盘。" },  // STR_W_T2_OFFER_HINT
  { "Zweiten Tag schreiben",
    "Write a second tag",
    "Écrire un second tag",
    "写入第二个标签" },  // STR_W_T2_START
  { "Fertig",
    "Done",
    "Terminer",
    "完成" },  // STR_W_T2_DONE_BTN
  { "Jetzt den zweiten Tag auflegen",
    "Now put the second tag on",
    "Posez le second tag",
    "请放上第二个标签" },  // STR_W_T2_WAIT
  { "Ersten Tag abnehmen, zweiten auf den Leser legen. Die Waage zeigt dieselbe Frage.",
    "Take the first tag off, put the second on the reader. The scale asks the same.",
    "Retirez le premier tag et posez le second sur le lecteur. La balance affiche la même demande.",
    "移开第一个标签，将第二个标签放到读卡器上（秤屏幕也会同步提示）。" },  // STR_W_T2_WAIT_HINT
  { "Noch %d s",
    "%d s left",
    "Encore %d s",
    "剩余 %d 秒" },  // STR_W_T2_LEFT
  { "Zweiter Tag wird verknüpft...",
    "Linking the second tag...",
    "Liaison du second tag...",
    "正在绑定第二个标签..." },  // STR_W_T2_LINKING
  { "Zweiter Tag verknüpft",
    "Second tag linked",
    "Second tag lié",
    "第二个标签已绑定" },  // STR_W_T2_OK
  { "Spule #%d wird jetzt von beiden Tags gefunden.",
    "Spool #%d is now found by both tags.",
    "Les deux tags mènent désormais à la bobine #%d.",
    "现在两个标签均可识别料盘 #%d。" },  // STR_W_T2_OK_HINT
  { "Zweiter Tag nicht verknüpft",
    "Second tag not linked",
    "Second tag non lié",
    "第二个标签绑定失败" },  // STR_W_T2_FAIL
  { "Kein zweiter Tag aufgelegt.",
    "No second tag was put on.",
    "Aucun second tag posé.",
    "未检测到第二个标签。" },  // STR_W_T2_EXPIRED
  { "Diesen Tag mit Spule #%d beschreiben?",
    "Write spool #%d to this tag?",
    "Écrire la bobine #%d sur ce tag ?",
    "将料盘 #%d 写入此标签？" },  // STR_W_ASK_WRITE
  { "Auf diesem Tag steht schon etwas",
    "This tag already holds something",
    "Ce tag contient déjà quelque chose",
    "此标签已有数据" },  // STR_W_ASK_OVER_TITLE
  { "Überschreiben mit Spule #%d?",
    "Overwrite it with spool #%d?",
    "L'écraser avec la bobine #%d ?",
    "是否用料盘 #%d 覆盖？" },  // STR_W_ASK_OVER
  { "Überschreiben",
    "Overwrite",
    "Écraser",
    "覆盖" },  // STR_W_ASK_YES_OVER
  { "Beschreiben",
    "Write",
    "Écrire",
    "写入" },  // STR_W_ASK_YES_WRITE
  { "Nicht angenommen: es wird schon geschrieben, oder die Spulen-ID fehlt.",
    "Not accepted: a write is already running, or the spool ID is missing.",
    "Refusé : une écriture est déjà en cours, ou l'ID de bobine manque.",
    "操作被拒绝：正在写入中，或缺少料盘 ID。" },  // STR_W_TW_REFUSED
  { "Erstnutzung", "First used", "1re util.", "首次使用" },  // STR_LBL_L_FIRST
  { "Angelegt",    "Added",      "Ajoutée",   "添加时间" },  // STR_LBL_L_ADDED
  { "TESTDRUCK",   "TEST PRINT", "TEST",      "测试打印" },  // STR_LBL_TEST_BAND
  { "Dieses Feature hat viel Zeit gekostet. Ich freue mich über eine Spende.",
    "This feature took a lot of time. I'd be glad about a donation.",
    "Cette fonction a pris beaucoup de temps. Un don me ferait plaisir.",
    "此功能耗费大量精力，欢迎打赏支持。" },  // STR_LBL_TEST_DONATE
  { "Alles eingerichtet", "All set",            "Tout est prêt",  "全部就绪" },  // STR_EF_HEAD_OK
  { "Es fehlen Felder",   "Fields are missing", "Champs absents", "存在未填项" },  // STR_EF_HEAD_MISSING
  { "Anlegen",            "Create",             "Créer",          "创建" },  // STR_EF_BTN_CREATE
  { "Kein Feld nötig",    "No field needed",    "Pas de champ",   "无需填写字段" },  // STR_EF_NATIVE_SUB
  { "Für das Update %s muss der Speicherbereich für die Firmware vergrößert werden. Das geht nur einmalig per USB-Kabel über den Web-Flasher: etwa 2 Minuten, alle Einstellungen bleiben erhalten. Danach kommen Updates wieder wie gewohnt drahtlos.",
    "For the update %s, the storage area for the firmware has to be enlarged. That only works once over a USB cable with the web flasher: about 2 minutes, every setting is kept. After that, updates arrive over the air as usual.",
    "Pour la mise à jour %s, la zone mémoire du firmware doit être agrandie. Cela ne se fait qu'une fois, par câble USB avec le Web Flasher : environ 2 minutes, tous les réglages sont conservés. Ensuite, les mises à jour arrivent sans fil comme avant.",
    "升级至 %s 需扩大固件存储分区。仅需通过 USB 数据线使用网页刷机工具操作一次（约 2 分钟，保留所有设置），此后即可恢复正常 OTA 无线升级。" },  // STR_PART_HINT_BLOCKED
  { "Später", "Later",
    "Plus tard",
    "稍后" },  // STR_PART_HINT_LATER
  { "Web-Flasher", "Web flasher",
    "Web Flasher",
    "网页刷机" },  // STR_PART_HINT_QR
  { "%s passt nicht mehr: einmal per USB flashen", "%s no longer fits: flash once over USB",
    "%s ne tient plus : flasher une fois par USB",
    "%s 空间不足：请通过 USB 刷机一次" },  // STR_GH_OTA_TOO_BIG
  { "Firmware wird hochgeladen", "Uploading the firmware",
    "Envoi du firmware",
    "正在上传固件" },  // STR_W_FW_UPLOADING
  { "Die Datei ist größer als der Speicher dieser Waage ({s}). Einmal per USB über den Web-Flasher aktualisieren, dann passt sie.",
    "The file is larger than the storage of this scale ({s}). Update once over USB with the web flasher, then it fits.",
    "Le fichier est plus grand que la mémoire de cette balance ({s}). Mettez à jour une fois par USB avec le Web Flasher, ensuite il tiendra.",
    "固件文件超出当前称重台存储容量 ({s})。请先通过 USB 使用网页刷机工具升级一次，之后即可正常使用。" },  // STR_W_FW_TOOBIG
  { "Bietet der Flasher \"Install\" statt \"Update\" an, das Häkchen bei \"Erase\" nicht setzen, sonst sind WLAN und Kalibrierung weg.",
    "If the flasher offers \"Install\" instead of \"Update\", leave the \"Erase\" box unticked, or WiFi and calibration are gone.",
    "Si le flasher propose « Install » au lieu de « Update », ne cochez pas « Erase », sinon le WiFi et l'étalonnage sont perdus.",
    "若刷机工具显示 \"Install\" 而非 \"Update\"，请勿勾选 \"Erase\"，否则将丢失 WiFi 与校准数据。" },  // STR_PART_HINT_ERASE
  { "Der Server hat das Anfangsgewicht nicht übernommen. Es gilt weiter der alte Wert.",
    "The server did not accept the initial weight. The old value still stands.",
    "Le serveur n'a pas accepté le poids initial. L'ancienne valeur reste valable.",
    "服务器未接受初始重量，仍保留原数值。" },  // STR_INIT_W_FAIL_TEXT
  // Empty spool weight typed in (issue #40)
  { "Leergewicht eingeben", "Enter empty spool weight",
    "Saisir le poids à vide",
    "输入空盘重量" },  // STR_TARE_ENTER_TITLE
  { "Waage %.0f g\n- Spule %.0f g\n= Rest %.0f g", "Scale %.0f g\n- spool %.0f g\n= %.0f g left",
    "Balance %.0f g\n- bobine %.0f g\n= reste %.0f g",
    "称重 %.0f g\n- 空盘 %.0f g\n= 剩余 %.0f g" },  // STR_TARE_ENTER_REST
  { "Leergewicht der Spule ohne Filament, %.0f bis %.0f g", "Weight of the spool without filament, %.0f to %.0f g",
    "Poids de la bobine sans filament, %.0f à %.0f g",
    "不含耗材的空料盘重量，%.0f 至 %.0f g" },  // STR_TARE_ENTER_RANGE
  { "Mehr als auf der Waage liegt", "More than is on the scale",
    "Dépasse le poids pesé",
    "超出当前称重值" },  // STR_TARE_ENTER_OVER
  // What else a Bambu tag says, on the tag card and the tags page
  { "Trocknen",     "Drying",        "Séchage",    "烘干" },  // STR_W_TAG_DRY
  { "Bambu-Code",   "Bambu code",    "Code Bambu", "Bambu 代码" },  // STR_W_TAG_CODE
  { "Zweite Farbe", "Second colour", "2e couleur", "第二颜色" },  // STR_W_TAG_COLOR2
  // The Bambu catalog's card on the tags page
  { "Bambu-Katalog", "Bambu catalog",
    "Catalogue Bambu",
    "Bambu 目录" },  // STR_W_BCAT_TITLE
  { "Noch nicht geladen.", "Not loaded yet.",
    "Pas encore chargé.",
    "尚未加载。" },  // STR_W_BCAT_NONE
  { "%d Farben, geladen am %s, zuletzt geprüft am %s.", "%d colours, loaded on %s, last checked on %s.",
    "%d couleurs, chargées le %s, dernière vérification le %s.",
    "共 %d 种颜色，加载于 %s，上次检查于 %s。" },  // STR_W_BCAT_STATE
  { "Wird geladen ...", "Loading ...",
    "Chargement ...",
    "正在加载..." },  // STR_W_BCAT_BUSY
  { "Laden fehlgeschlagen: %s.", "Loading failed: %s.",
    "Échec du chargement : %s.",
    "加载失败：%s。" },  // STR_W_BCAT_FAIL
  { "Laden", "Load",
    "Charger",
    "加载" },  // STR_W_BCAT_LOAD
  { "Aktualisieren", "Update",
    "Mettre à jour",
    "更新" },  // STR_W_BCAT_UPDATE
  { "Die Waage holt die Farbtabelle aus BambuStudio (GitHub, rund 230 KB) und speichert eine kompakte Kopie. Danach zeigt sie bei jedem Bambu-Tag den Farbnamen und die Artikelnummer, auch ohne Internet. Bambu ergänzt die Tabelle, wenn neue Farben erscheinen: Die Waage sieht einmal am Tag nach und lädt nur, wenn sich etwas geändert hat. Das folgt dem Schalter für den automatischen Update-Check.",
    "The scale fetches the colour table from BambuStudio (GitHub, about 230 KB) and keeps a compact copy. From then on it shows the colour name and article number of every Bambu tag, offline as well. Bambu extends the table when new colours come out: the scale looks once a day and only downloads when something changed. This follows the switch for the automatic update check.",
    "La balance récupère la table des couleurs de BambuStudio (GitHub, environ 230 ko) et en garde une copie compacte. Elle affiche ensuite le nom de la couleur et la référence article de chaque tag Bambu, même hors ligne. Bambu complète la table à la sortie de nouvelles couleurs : la balance vérifie une fois par jour et ne télécharge que si quelque chose a changé. Cela dépend de l'option de recherche automatique des mises à jour.",
    "称重台会从 BambuStudio（GitHub，约 230 KB）获取颜色表并保存精简副本。此后即可离线显示每个 Bambu 标签的颜色名称和料号。Bambu 推出新颜色时会更新该表：称重台每天检查一次，仅在有变动时下载（随自动更新检查开关生效）。" },  // STR_W_BCAT_NOTE
  { "Unverändert, nichts neu geladen.", "Unchanged, nothing downloaded.",
    "Inchangé, rien téléchargé.",
    "无变化，未下载新数据。" },  // STR_W_BCAT_UNCHANGED
  // https to the backend
  { "Zertifikat nicht prüfen (nur bei https)", "Do not check the certificate (https only)",
    "Ne pas vérifier le certificat (https uniquement)",
    "不验证证书（仅限 https）" },  // STR_W_TLS_INSECURE
  { "Eine Adresse mit https:// wird verschlüsselt angesprochen. Öffentliche Zertifikate wie Let's Encrypt prüft die Waage selbst. Zeigt der Browser bei deinem Server eine Warnung, weil das Zertifikat selbst signiert ist, schalte das hier ein: Die Verbindung bleibt verschlüsselt, die Waage prüft aber nicht, wer antwortet.",
    "An address with https:// is reached encrypted. Public certificates such as Let's Encrypt are checked by the scale itself. If your browser warns about your server because its certificate is self-signed, switch this on: the connection stays encrypted, but the scale does not check who answers.",
    "Une adresse en https:// est contactée de façon chiffrée. La balance vérifie elle-même les certificats publics comme Let's Encrypt. Si votre navigateur affiche un avertissement pour votre serveur parce que son certificat est auto-signé, activez ceci : la connexion reste chiffrée, mais la balance ne vérifie pas qui répond.",
    "https:// 地址采用加密连接。Let's Encrypt 等公共证书可由称重台自动验证。若因服务器使用自签名证书导致浏览器发出警告，请开启此项：连接仍保持加密，但称重台不再验证服务器身份。" },  // STR_W_TLS_INSECURE_HINT
  { "Verbindung offen halten (nur bei https)", "Keep the connection open (https only)",
    "Garder la connexion ouverte (https uniquement)",
    "保持连接开启（仅限 https）" },  // STR_W_TLS_KEEP
  { "Der Aufbau einer https-Verbindung dauert auf der Waage etwa 0,6 s, eine offene Verbindung antwortet in rund 30 ms. Die Waage öffnet sie schon, wenn eine Spule aufgelegt wird, und schließt sie nach der gewählten Zeit ohne Anfrage. 30 Minuten lohnen sich nur, wenn dein Server die Verbindung so lange offen lässt.",
    "Opening an https connection takes the scale about 0.6 s, an open connection answers in about 30 ms. The scale opens it as soon as a spool is put on, and closes it after the chosen time without a request. 30 minutes only pay off if your server keeps the connection open that long.",
    "Ouvrir une connexion https prend environ 0,6 s à la balance, une connexion ouverte répond en 30 ms environ. La balance l'ouvre dès qu'une bobine est posée et la ferme si aucune requête n'arrive pendant le délai choisi. 30 minutes ne servent que si votre serveur garde la connexion ouverte aussi longtemps.",
    "称重台建立 https 连接约需 0.6 秒，而保持连接的响应仅需约 30 毫秒。放上料盘时连接即会建立，并在无请求达到设定时间后关闭。仅当您的服务器同样支持保持连接 30 分钟时，设为 30 分钟才有意义。" },  // STR_W_TLS_KEEP_HINT
  // The address screen on the device
  { "https-Adresse", "https address", "Adresse https", "https 地址" },  // STR_SP_HTTPS_TITLE
  // The printer page's print position card, and the calibration page
  { "Druckposition", "Print position", "Position d'impression",
    "打印位置" },  // STR_W_P_CAL_TITLE
  { "Lage der Rolle", "Roll position", "Position du rouleau",
    "纸卷位置" },  // STR_W_P_CAL_ROLL
  { "Links",                  "Left",                   "Gauche",                        "居左" },  // STR_W_P_CAL_LEFT
  { "Mitte", "Centre", "Centre",
    "居中" },  // STR_W_P_CAL_CENTER
  { "Rechts",                 "Right",                  "Droite",                        "居右" },  // STR_W_P_CAL_RIGHT
  { "Versatz", "Offset", "Décalage",
    "偏移量" },  // STR_W_P_CAL_OFFSET
  { "Kalibrierseite drucken", "Print calibration page", "Imprimer la page de calibrage",
    "打印校准页" },  // STR_W_P_CAL_PRINT
  { "Trag die erste Zahl ein, die links auf dem Etikett steht. Sitzt der Rahmen danach nicht mittig, stell mit − und + nach.",
    "Enter the first number on the left of the label. If the frame is not centred afterwards, adjust with − and +.",
    "Saisissez le premier nombre à gauche de l'étiquette. Si le cadre n'est pas centré ensuite, ajustez avec − et +.",
    "输入标签左侧的第一个数字。如果之后边框未居中，请使用 − 和 + 微调。" },  // STR_W_P_CAL_HINT
  { "Erste Zahl links = Versatz", "Leftmost number = offset", "Nombre à gauche = décalage",
    "最左数字 = 偏移量" },  // STR_LBL_CAL_EDGE
  { "Mehr als 1 mm Rand links und rechts vom Rahmen: Etikettgröße prüfen.",
    "More than 1 mm margin left and right of the frame: check the label size.",
    "Plus de 1 mm de marge à gauche et à droite du cadre : vérifiez la taille de l'étiquette.",
    "边框左右留白均超过 1 mm：请检查标签尺寸。" },  // STR_W_P_CAL_HINT2
  // The print position screen on the device
  { "Kalibrierseite drucken, dann die erste Zahl links auf dem Etikett einstellen.",
    "Print the calibration page, then set the first number on the left of the label.",
    "Imprimez la page de calibrage, puis reportez ici le 1er nombre à gauche.",
    "打印校准页，然后设置标签左侧的第一个数字。" },  // STR_PRN_OFFSET_HINT
  { "Wo die Rolle unter dem Druckkopf läuft, hängt davon ab, wie sie im Halter sitzt. Die Kalibrierseite druckt ein Lineal über den ganzen Kopf: Die erste Zahl links auf dem Etikett ist der Versatz. Sitzt der Rahmen danach mit gleichem Rand links und rechts, passt es. Gedrückt halten zählt schnell.",
    "Where the roll runs under the head depends on how it sits in the holder. The calibration page prints a ruler across the whole head: the first number on the left of the label is the offset. Once the frame has the same margin left and right, it is right. Hold a button to count fast.",
    "Le passage du rouleau sous la tête dépend de sa place dans le support. La page de calibrage imprime une règle sur toute la tête : le premier nombre à gauche de l'étiquette est le décalage. Quand le cadre a la même marge des deux côtés, c'est bon. Maintenez un bouton pour aller vite.",
    "卷纸在打印头下的走纸位置取决于它在支架中的摆放。校准页会沿整个打印头打印标尺：标签左侧的第一个数字即为偏移量。当边框左右留白相等时，即表示校准准确。长按按钮可快速增减。" },  // STR_PRN_OFFSET_HELP
  // Thermal labels and the dryer
  { "Beim Trocknen mit hoher Temperatur wird das Etikett auf der Spule schwarz.",
    "Drying at a high temperature turns the label on the spool black.",
    "Un séchage à haute température noircit l'étiquette sur la bobine.",
    "高温烘干会导致料盘上的标签变黑。" },  // STR_PRN_HEAT_SHORT
  { "Die Etiketten sind Thermopapier: Der Drucker färbt sie ohne Tinte, allein mit Wärme. Dieselbe Reaktion löst auch das Trocknen aus. Auf einer Spule, die mit hoher Temperatur getrocknet wird, färbt sich das ganze Etikett schwarz, im AMS HT bei 85 °C meist schon beim ersten Mal. Bei niedrigeren Temperaturen geschieht das langsamer und kann sich über mehrere Trocknungen aufbauen. Schrift und QR-Code sind danach nicht mehr lesbar.",
    "The labels are thermal paper: the printer colours them without ink, by heat alone. Drying sets off the same reaction. On a spool dried at a high temperature the whole label turns black, in the AMS HT at 85 °C mostly the very first time. At lower temperatures it happens more slowly and can build up over several drying runs. Text and QR code can no longer be read afterwards.",
    "Les étiquettes sont en papier thermique : l'imprimante les colore sans encre, par la chaleur. Le séchage déclenche la même réaction. Sur une bobine séchée à haute température, toute l'étiquette noircit, dans l'AMS HT à 85 °C souvent dès la première fois. Plus bas, cela va plus lentement et peut s'accumuler sur plusieurs séchages. Texte et code QR deviennent illisibles.",
    "标签采用热敏纸材质：打印机无需墨水，仅靠加热即可显色。烘干同样会触发此反应。高温烘干料盘时，整张标签都会变黑；在 85 °C 的 AMS HT 中通常首次烘干就会发生。较低温度下变黑较慢，但经过多次烘干后仍会逐渐加深。变黑后文字和 QR 码将无法识别。" },  // STR_PRN_HEAT_HELP
  // A Bambu tag that does not describe the spool it is linked to
  { "Passt nicht zum Tag", "Does not match the tag", "Diffère du tag",  "与标签不匹配" },  // STR_LINK_MISMATCH_TITLE
  { "Trotzdem verknüpfen", "Link anyway",            "Lier quand même", "仍要绑定" },  // STR_BTN_LINK_ANYWAY
  { "Tag passt nicht zur Spule", "Tag does not match the spool",
    "Le tag ne correspond pas",
    "标签与料盘不匹配" },  // STR_TAG_MISMATCH_STATUS
  { "Der Tag passt nicht zu Spule #%d.\nTag: %s\nSpule: %s\nTrotzdem verknüpfen?",
    "The tag does not match spool #%d.\nTag: %s\nSpool: %s\nLink anyway?",
    "Le tag ne correspond pas à la bobine #%d.\nTag : %s\nBobine : %s\nLier quand même ?",
    "该标签与料盘 #%d 不匹配。\n标签：%s\n料盘：%s\n仍要绑定吗？" },  // STR_W_TL_MISMATCH
  { "Anzeige: Spule #%d", "Showing spool #%d", "Vue : bobine #%d", "正在显示料盘 #%d" },  // STR_TAG_VIEW_SPOOL
  // Web: theme
  { "Theme", "Theme", "Thème", "主题" },  // STR_W_NAV_THEME
  { "Theme", "Theme", "Thème", "主题" },  // STR_W_C_THEME
  { "Gilt für die Waage und diese Weboberfläche. Die Waage startet dafür neu, alle Einstellungen bleiben erhalten.",
    "Applies to the scale and to this web interface. The scale restarts for it; every setting is kept.",
    "S'applique à la balance et à cette interface web. La balance redémarre pour cela, tous les réglages sont conservés.",
    "同时应用于秤和此 Web 界面。生效需重启秤，所有设置均会保留。" },  // STR_W_THEME_HINT
  { "Dunkel", "Dark",
    "Sombre",
    "深色" },  // STR_W_THEME_DARK
  { "Hell", "Light",
    "Clair",
    "浅色" },  // STR_W_THEME_LIGHT
  { "Aktiv", "Active",
    "Actif",
    "当前启用" },  // STR_W_THEME_ACTIVE
  { "Übernehmen und neu starten", "Apply and restart",
    "Appliquer et redémarrer",
    "应用并重启" },  // STR_W_THEME_APPLY
  { "Gespeichert. Gilt ab dem nächsten Neustart der Waage.", "Saved. Takes effect when the scale next restarts.",
    "Enregistré. Actif au prochain redémarrage de la balance.",
    "已保存，将在下次重启秤时生效。" },  // STR_W_THEME_LATER
  { "Die Waage startet neu, die Seite lädt gleich von selbst.", "The scale is restarting, this page reloads by itself.",
    "La balance redémarre, la page se recharge d'elle-même.",
    "秤正在重启，此页面将自动刷新。" },  // STR_W_THEME_RESTARTING
  { "Spoolman dunkel", "Spoolman dark",
    "Spoolman sombre",
    "Spoolman 深色" },  // STR_W_THEME_SPOOLMAN_DARK
  { "Spoolman hell", "Spoolman light",
    "Spoolman clair",
    "Spoolman 浅色" },  // STR_W_THEME_SPOOLMAN_LIGHT
  { "FilaMan dunkel", "FilaMan dark",
    "FilaMan sombre",
    "FilaMan 深色" },  // STR_W_THEME_FILAMAN_DARK
  { "FilaMan hell", "FilaMan light",
    "FilaMan clair",
    "FilaMan 浅色" },  // STR_W_THEME_FILAMAN_LIGHT
  { "Farben vom Backend", "Backend colours",
    "Couleurs du backend",
    "后端配色" },  // STR_W_THEME_FOLLOW_H
  { "Farben folgen dem Backend", "Colours follow the backend",
    "Les couleurs suivent le backend",
    "配色跟随后端" },  // STR_W_THEME_FOLLOW
  { "Spoolman, FilaMan, BamBuddy und Spooly bringen je eigene Farben mit. Hell oder dunkel kommt aus deiner Wahl oben.", "Spoolman, FilaMan, BamBuddy and Spooly each bring their own colours. Light or dark comes from your choice above.",
    "Spoolman, FilaMan, BamBuddy et Spooly apportent chacun leurs propres couleurs. Clair ou sombre suit votre choix ci-dessus.",
    "Spoolman、FilaMan、BamBuddy 和 Spooly 各自拥有专属配色。深色或浅色模式由上方选择决定。" },  // STR_W_THEME_FOLLOW_HINT
  { "Theme nach dem Neustart", "Theme after restart",
    "Thème après redémarrage",
    "重启后的主题" },  // STR_W_THEME_AFTER
  { "Eigene Farben", "Your own colours",
    "Vos couleurs",
    "自定义配色" },  // STR_W_THEME_OWN_H
  { "Auf dem gewählten Theme. Jede Farbe behält ihre Helligkeit, Text bleibt so gut lesbar wie vorher.", "On top of the theme. Every colour keeps its brightness, so text stays as readable as before.",
    "Par-dessus le thème. Chaque couleur garde sa luminosité, le texte reste aussi lisible qu'avant.",
    "叠加在所选主题之上。每种颜色均保持原有亮度，确保文字依然清晰易读。" },  // STR_W_THEME_OWN_HINT
  { "Akzent", "Accent",
    "Accent",
    "强调色" },  // STR_W_THEME_ACCENT
  { "Titel, aktive Auswahl, Schieberegler, Links.", "Titles, the active choice, sliders, links.",
    "Titres, choix actif, curseurs, liens.",
    "用于标题、当前选中项、滑块及链接。" },  // STR_W_THEME_ACCENT_HINT
  { "Grundton", "Ground tone",
    "Teinte de fond",
    "主色调" },  // STR_W_THEME_TONE
  { "Hintergrund, Flächen, Linien und die graue Schrift.", "Background, surfaces, lines and the grey text.",
    "Fond, surfaces, lignes et texte gris.",
    "用于背景、卡片表面、分隔线及灰色文字。" },  // STR_W_THEME_TONE_HINT
  { "Vom Theme", "Theme's own",
    "Celle du thème",
    "主题默认" },  // STR_W_THEME_SCHEME_OWN
  { "Eigene Farbe", "Own colour",
    "Couleur libre",
    "自定义颜色" },  // STR_W_THEME_OWN_COLOUR
  { "Farbton", "Hue",
    "Teinte",
    "色相" },  // STR_W_THEME_HUE
  { "Stärke", "Strength",
    "Intensité",
    "饱和度" },  // STR_W_THEME_STRENGTH
  { "Links grau, in der Mitte wie das Theme, rechts kräftiger.", "Grey on the left, as the theme in the middle, stronger on the right.",
    "Gris à gauche, comme le thème au milieu, plus soutenu à droite.",
    "左侧偏灰，中间与主题一致，右侧更浓郁。" },  // STR_W_THEME_STRENGTH_HINT
  { "Vorschau", "Preview",
    "Aperçu",
    "预览" },  // STR_W_THEME_PREVIEW
  { "Zurück zu den Farben des Themes", "Back to the theme's colours",
    "Revenir aux couleurs du thème",
    "恢复主题默认配色" },  // STR_W_THEME_RESET
  { "auf dem Hintergrund", "on the background",
    "sur le fond",
    "于背景之上" },  // STR_W_THEME_ON_BG
  { "+ eigene Farben", "+ own colours",
    "+ couleurs perso",
    "+ 自定义颜色" },  // STR_W_THEME_PLUS_OWN
  { "Orange", "Orange",
    "Orange",
    "橙色" },  // STR_W_COL_ORANGE
  { "Pink", "Pink",
    "Rose",
    "粉色" },  // STR_W_COL_PINK
  { "Blau", "Blue",
    "Bleu",
    "蓝色" },  // STR_W_COL_BLUE
  { "Violett", "Violet",
    "Violet",
    "紫色" },  // STR_W_COL_VIOLET
  { "Gelb", "Yellow",
    "Jaune",
    "黄色" },  // STR_W_COL_YELLOW
  { "Petrol", "Petrol",
    "Pétrole",
    "蓝绿色" },  // STR_W_COL_PETROL
  { "Rot", "Red",
    "Rouge",
    "红色" },  // STR_W_COL_RED
  { "Grün", "Green",
    "Vert",
    "绿色" },  // STR_W_COL_GREEN
  { "Sand", "Sand",
    "Sable",
    "沙色" },  // STR_W_COL_SAND
  { "Helle Themes: Beim Scrollen und beim Wechsel zwischen Screens zeigt das Display sichtbare Schlieren, weil es jedes Bild in Streifen aufbaut. Dunkle Themes wirken dabei ruhiger.",
    "Light themes: while scrolling and when screens change, the display shows visible smearing, because it builds every frame in strips. Dark themes look calmer there.",
    "Thèmes clairs : pendant le défilement et lors des changements d'écran, l'affichage laisse des traînées visibles, car il construit chaque image par bandes. Les thèmes sombres paraissent plus calmes.",
    "浅色主题：由于屏幕逐条刷新画面，滚动或切换页面时会出现明显拖影；深色主题下视觉效果更平稳。" },  // STR_W_THEME_LIGHT_NOTE
  { "Tag gehört zu Filament #%d", "Tag belongs to filament #%d",
    "Tag lié au filament #%d",
    "标签属于耗材 #%d" },  // STR_TAG_ON_FILAMENT
  { "Server verlangt einen Zugang", "Server asks for access",
    "Authentification requise",
    "服务器需要验证" },  // STR_SM_AUTH_MISSING
  { "Zugang abgelehnt", "Access rejected",
    "Accès refusé",
    "访问被拒绝" },  // STR_SM_AUTH_REJECTED
  { "Nur ausfüllen, wenn ein Proxy mit Passwort davor steht oder der Server einen Schlüssel verlangt.", "Only fill this in when a proxy with a password sits in front of it or the server asks for a key.",
    "À remplir seulement si un proxy protégé par mot de passe se trouve devant le serveur, ou si le serveur demande une clé.",
    "仅当服务器前置了密码代理或需要密钥验证时才需填写。" },  // STR_W_SM_AUTH_HINT
  { "Zugang", "Access",
    "Accès",
    "验证方式" },  // STR_W_SM_AUTH_KIND
  { "Keiner", "None",
    "Aucun",
    "无" },  // STR_W_SM_AUTH_NONE
  { "API-Key (X-API-Key)", "API key (X-API-Key)",
    "Clé d'API (X-API-Key)",
    "API 密钥 (X-API-Key)" },  // STR_W_SM_AUTH_KEY
  { "Token (Bearer)", "Token (Bearer)",
    "Jeton (Bearer)",
    "令牌 (Bearer)" },  // STR_W_SM_AUTH_BEARER
  { "Benutzer und Passwort", "User and password",
    "Utilisateur et mot de passe",
    "用户名和密码" },  // STR_W_SM_AUTH_BASIC
  { "Benutzer", "User",
    "Utilisateur",
    "用户名" },  // STR_W_SM_USER
  { "Schlüssel oder Passwort", "Key or password",
    "Clé ou mot de passe",
    "密钥或密码" },  // STR_W_SM_SECRET
  { "Die Adresse beginnt mit http://, der Zugang geht also unverschlüsselt durchs Netz. Schützt vor fremden Schreibzugriffen, nicht vor Mitlesen im selben Netz.", "The address starts with http://, so the access crosses the network unencrypted. It keeps others from writing, not from listening on the same network.",
    "L'adresse commence par http:// : les identifiants circulent donc en clair sur le réseau. Cela empêche les écritures par des tiers, mais pas l'écoute sur le même réseau.",
    "该地址以 http:// 开头，凭据将以明文在网络中传输。这只能防止他人写入，无法防止同网络下的窃听。" },  // STR_W_SM_AUTH_PLAIN
  { "Webseite", "Web page",
    "Page web",
    "网页端" },  // STR_W_THEME_WEB_H
  { "Hell oder dunkel wie das System", "Light or dark as the system sets it",
    "Clair ou sombre selon le système",
    "跟随系统浅色或深色模式" },  // STR_W_THEME_WEB_OS
  { "Nur diese Webseite: Sie folgt der Einstellung von Gerät oder Browser, in der Farbfamilie der Waage. Die Waage bleibt, wie oben gewählt. Wirkt sofort, ohne Neustart.", "This web page only: it follows the device or browser setting, in the scale's colour family. The scale stays as chosen above. Takes effect at once, without a restart.",
    "Cette page web uniquement : elle suit le réglage de l'appareil ou du navigateur, dans la famille de couleurs de la balance. La balance garde le thème choisi ci-dessus. Effet immédiat, sans redémarrage.",
    "仅限当前网页：随设备或浏览器设置切换，沿用秤的色系。秤本身保持上方所选主题。立即生效，无需重启。" },  // STR_W_THEME_WEB_OS_HINT
  { "Zu lang: höchstens %u Zeichen. Nichts gespeichert.", "Too long: %u characters at most. Nothing saved.",
    "Trop long : %u caractères au maximum. Rien n'a été enregistré.",
    "内容过长：最多 %u 个字符，未保存。" },  // STR_W_SM_SECRET_LONG
  { "Der Zugang wurde für %s eingegeben und geht nicht an die neue Adresse. Bitte für diese Adresse neu eingeben.", "This access was entered for %s and is not sent to the new address. Enter it again for this address.",
    "Ces identifiants ont été saisis pour %s et ne sont pas envoyés à la nouvelle adresse. Saisissez-les à nouveau pour cette adresse.",
    "此凭据原用于 %s，不会发送至新地址。请为当前地址重新输入。" },  // STR_W_SM_AUTH_REBIND
  { "Für Schrift wird die Helligkeit angepasst, bis sie lesbar ist, auf der Waage wie hier. Flächen behalten die gewählte Farbe.",
    "For text its lightness is adjusted until it reads, on the scale as here. Fills keep the chosen colour.",
    "Pour le texte, la luminosité est ajustée jusqu'à ce qu'il soit lisible, sur la balance comme ici. Les surfaces gardent la couleur choisie.",
    "为保证清晰易读，文字亮度会自动调整（秤端与此处一致），背景填充则保留所选颜色。" },  // STR_W_THEME_TEXT_ADJUSTED
  { "Die Farben folgen dem Backend und wechseln beim nächsten Neustart der Waage.",
    "The colours follow the backend and change when the scale next restarts.",
    "Les couleurs suivent le backend et changent au prochain redémarrage de la balance.",
    "配色将跟随后端设置，并在秤下次重启时生效。" },  // STR_W_BACKEND_THEME_NOTE
  { "Eigene Farben zurücksetzen", "Reset own colours",
    "Effacer les couleurs perso",
    "重置自定义配色" },  // STR_THEME_RESET_OWN
  { "Akzent und Grundton aus dem Web", "Accent and ground tone from the web",
    "Accent et teinte de fond du web",
    "网页端设置的强调色与底色" },  // STR_THEME_RESET_OWN_SUB
  { "Noch nicht übernommen", "Not applied yet",
    "Pas encore appliqué",
    "尚未应用" },  // STR_W_THEME_UNSAVED
  { "Ins AMS", "Into AMS", "Dans l'AMS", "放入 AMS" },  // STR_AMS_MAIN_ASSIGN
  { "Display-Screenshot",
    "Display screenshot",
    "Capture d'écran",
    "屏幕截图" },  // STR_W_C_SHOT
  { "Bilder der aktuellen Anzeige für Issues und Pull Requests. An der Waage selbst: zwei Finger eine Sekunde aufs Display legen, bis es kurz dunkel wird. Bis zu 6 Bilder bleiben bis zum Neustart hier, das älteste fällt zuerst raus.",
    "Pictures of what the display shows, for issues and pull requests. On the scale itself: rest two fingers on the display for a second until it blinks dark. Up to 6 pictures stay here until the next restart, the oldest goes first.",
    "Images de l'affichage actuel, pour les issues et les pull requests. Sur la balance elle-même : posez deux doigts sur l'écran pendant une seconde, jusqu'à ce qu'il s'assombrisse brièvement. Jusqu'à 6 images restent ici jusqu'au prochain redémarrage ; la plus ancienne est supprimée en premier.",
    "当前屏幕显示画面截图，用于提交 Issue 或 Pull Request。在秤上操作：双指按住屏幕一秒，直至屏幕短暂变暗即可截屏。重启前最多保留 6 张截图，超出时最早的将被覆盖。" },  // STR_W_SHOT_NOTE
  { "Aufnehmen",
    "Capture",
    "Capturer",
    "截图" },  // STR_W_SHOT_TAKE
  { "Nimmt auf...",
    "Capturing...",
    "Capture en cours...",
    "正在截图..." },  // STR_W_SHOT_BUSY
  { "Alle speichern",
    "Save all",
    "Tout enregistrer",
    "全部保存" },  // STR_W_SHOT_SAVE_ALL
  { "Alle löschen",
    "Delete all",
    "Tout supprimer",
    "全部删除" },  // STR_W_SHOT_DROP_ALL
  { "Aufgenommen um {t}",
    "Captured at {t}",
    "Capturée à {t}",
    "网页截图于 {t}" },  // STR_W_SHOT_AT_WEB
  { "An der Waage aufgenommen um {t}",
    "Captured on the scale at {t}",
    "Capturée sur la balance à {t}",
    "设备截图于 {t}" },  // STR_W_SHOT_AT_PANEL
  { "Screenshot fehlgeschlagen",
    "Screenshot failed",
    "Échec de la capture",
    "截图失败" },  // STR_W_SHOT_FAIL
  { "Noch keine Screenshots.",
    "No screenshots yet.",
    "Aucune capture pour l'instant.",
    "暂无截图。" },  // STR_W_SHOT_EMPTY
  { "Filament wird gesucht ...",
    "Looking for the filament ...",
    "Recherche du filament ...",
    "正在查找耗材..." },  // STR_TAGNEW_SEARCHING
  { "Filament vorhanden: #%d",
    "Filament exists: #%d",
    "Filament existant : #%d",
    "耗材已存在：#%d" },  // STR_TAGNEW_FOUND
  { "Neues Filament aus der SpoolmanDB",
    "New filament from SpoolmanDB",
    "Nouveau filament de SpoolmanDB",
    "从 SpoolmanDB 新建耗材" },  // STR_TAGNEW_FROM_DB
  { "Neues Filament aus dem Tag",
    "New filament from the tag",
    "Nouveau filament du tag",
    "从标签新建耗材" },  // STR_TAGNEW_FROM_TAG
  { "BamBuddy legt die Spule direkt an",
    "BamBuddy creates the spool directly",
    "BamBuddy crée la bobine",
    "BamBuddy 将直接创建料盘" },  // STR_TAGNEW_BAMBUDDY
  { "Bambu-Katalog fehlt (Tags-Seite)",
    "Bambu catalog missing (tags page)",
    "Catalogue Bambu absent (page Tags)",
    "缺少 Bambu 目录（标签页）" },  // STR_TAGNEW_NEEDS_CATALOG
  { "Suche fehlgeschlagen (HTTP %d)",
    "Lookup failed (HTTP %d)",
    "Recherche échouée (HTTP %d)",
    "查询失败 (HTTP %d)" },  // STR_TAGNEW_FAILED
  { "Wird angelegt ...",
    "Creating ...",
    "Création ...",
    "正在创建..." },  // STR_TAGNEW_CREATING
  { "Anlegen fehlgeschlagen (HTTP %d)",
    "Could not create (HTTP %d)",
    "Création impossible (HTTP %d)",
    "创建失败 (HTTP %d)" },  // STR_TAGNEW_CREATE_FAIL
  { "Filament #%d angelegt, Spule nicht (HTTP %d)",
    "Filament #%d created, spool not (HTTP %d)",
    "Filament #%d créé, bobine non (HTTP %d)",
    "已建耗材 #%d，料盘失败 (HTTP %d)" },  // STR_TAGNEW_FILAMENT_ONLY
  { "Filament und Spule angelegt!",
    "Filament and spool created!",
    "Filament et bobine créés !",
    "耗材与料盘创建成功！" },  // STR_TAGNEW_OK_BOTH
  { "Ohne Antwort - erst Inventar prüfen",
    "No answer - check inventory first",
    "Sans réponse - vérifier l'inventaire",
    "无响应 - 请先检查库存" },  // STR_TAGNEW_SPOOL_UNSURE
  { "Vorlagen", "Presets",
    "Modèles",
    "预设主题" },  // STR_W_THEME_PRESETS
  { "Setzt Akzent, Grundton und Stärke auf einmal. Hell oder dunkel bleibt wie oben gewählt.", "Sets accent, ground tone and strength at once. Light or dark stays as chosen above.",
    "Règle accent, teinte de fond et intensité d'un coup. Clair ou sombre reste comme choisi plus haut.",
    "一键设置强调色、底色与浓度，深浅模式保持上方所选不变。" },  // STR_W_THEME_PRESETS_HINT
  { "BamBuddy dunkel", "BamBuddy dark",
    "BamBuddy sombre",
    "BamBuddy 深色" },  // STR_W_THEME_BAMBUDDY_DARK
  { "BamBuddy hell", "BamBuddy light",
    "BamBuddy clair",
    "BamBuddy 浅色" },  // STR_W_THEME_BAMBUDDY_LIGHT
  { "Preis",
    "Price",
    "Prix",
    "价格" },  // STR_TAGNEW_PRICE_BTN
  { "Preis der Spule",
    "Price of the spool",
    "Prix de la bobine",
    "料盘价格" },  // STR_PRICE_PAD_TITLE
  { "Leer = kein Preis. Währung wie im Server eingestellt.",
    "Empty = no price. Currency as set on the server.",
    "Vide = sans prix. Devise réglée sur le serveur.",
    "留空 = 无价格，货币单位以服务器设置为准。" },  // STR_PRICE_PAD_INFO
  { "Spule angelegt, Preis nicht gespeichert",
    "Spool created, price not saved",
    "Bobine créée, prix non enregistré",
    "料盘已创建，但价格未保存" },  // STR_TAGNEW_PRICE_LOST
  { "Neu aus Datenbank",
    "New from database",
    "Nouvelle de la base",
    "从数据库新建" },  // STR_DBPICK_BTN
  { "Filament-Datenbank wird geladen",
    "Loading the filament database",
    "Lecture de la base de filaments",
    "正在加载耗材数据库" },  // STR_DBPICK_LOADING
  { "Hersteller wählen",
    "Choose vendor",
    "Choisir le fabricant",
    "选择厂商" },  // STR_DBPICK_MAKER_TITLE
  { "Schon im Bestand",
    "Already in the inventory",
    "Déjà dans l'inventaire",
    "库存中已有" },  // STR_DBPICK_OWNED
  { "Weitere Hersteller A-Z",
    "Other vendors A-Z",
    "Autres fabricants A-Z",
    "其他厂商 A-Z" },  // STR_DBPICK_OTHER_MAKERS
  { "Nicht dabei? Dann direkt am Server anlegen.",
    "Not listed? Create it on the server instead.",
    "Absent ? Le créer sur le serveur.",
    "未找到？请直接在服务器上创建。" },  // STR_DBPICK_NOT_LISTED
  { "Farbe wählen",
    "Choose colour",
    "Choisir la couleur",
    "选择颜色" },  // STR_DBPICK_COLOR_TITLE
  { "Alle (%d)",
    "All (%d)",
    "Toutes (%d)",
    "全部 (%d)" },  // STR_DBPICK_ALL
  { "Rot",
    "Red",
    "Rouge",
    "红色" },  // STR_DBPICK_FAM_RED
  { "Orange",
    "Orange",
    "Orange",
    "橙色" },  // STR_DBPICK_FAM_ORANGE
  { "Gelb",
    "Yellow",
    "Jaune",
    "黄色" },  // STR_DBPICK_FAM_YELLOW
  { "Grün",
    "Green",
    "Vert",
    "绿色" },  // STR_DBPICK_FAM_GREEN
  { "Blau",
    "Blue",
    "Bleu",
    "蓝色" },  // STR_DBPICK_FAM_BLUE
  { "Lila",
    "Purple",
    "Violet",
    "紫色" },  // STR_DBPICK_FAM_PURPLE
  { "Pink",
    "Pink",
    "Rose",
    "粉色" },  // STR_DBPICK_FAM_PINK
  { "Braun",
    "Brown",
    "Marron",
    "棕色" },  // STR_DBPICK_FAM_BROWN
  { "Schwarz",
    "Black",
    "Noir",
    "黑色" },  // STR_DBPICK_FAM_BLACK
  { "Grau",
    "Grey",
    "Gris",
    "灰色" },  // STR_DBPICK_FAM_GREY
  { "Weiß",
    "White",
    "Blanc",
    "白色" },  // STR_DBPICK_FAM_WHITE
  { "Mehrfarbig",
    "Multicolour",
    "Multicolore",
    "多色" },  // STR_DBPICK_FAM_MULTI
  { "Klar",
    "Clear",
    "Transparent",
    "透明" },  // STR_DBPICK_FAM_CLEAR
  { "Welche Spulengröße?",
    "Which spool size?",
    "Quelle taille de bobine ?",
    "选择料盘规格" },  // STR_DBPICK_SIZE_TITLE
  { "Die Auswahl aus der Datenbank braucht Spoolman 0.27 oder neuer.",
    "Picking from the database needs Spoolman 0.27 or newer.",
    "Le choix dans la base demande Spoolman 0.27 ou plus récent.",
    "从数据库选择需 Spoolman 0.27 或更高版本。" },  // STR_DBPICK_NEEDS_NEWER
  { "Filament-Datenbank laden fehlgeschlagen (HTTP %d)",
    "Loading the filament database failed (HTTP %d)",
    "Échec de lecture de la base de filaments (HTTP %d)",
    "耗材数据库加载失败 (HTTP %d)" },  // STR_DBPICK_FAILED
  { "Keine Filamente mit 1,75 mm gefunden.",
    "No 1.75 mm filaments found.",
    "Aucun filament de 1,75 mm trouvé.",
    "未找到 1.75 mm 耗材。" },  // STR_DBPICK_EMPTY
  { "Produktlinie wählen",
    "Choose product line",
    "Choisir la gamme",
    "选择产品系列" },  // STR_DBPICK_LINE_TITLE
  { "Sonstige",
    "Other",
    "Autres",
    "其他" },  // STR_DBPICK_LINE_OTHER
  { "Hersteller über die Buchstaben oben wählen.",
    "Pick a vendor by its letter above.",
    "Choisissez le fabricant par sa lettre ci-dessus.",
    "请点击上方字母选择品牌。" },  // STR_DBPICK_PICK_LETTER
  { "Die Auswahl aus der Datenbank braucht das FilamentDB-Plugin in FilaMan.",
    "Picking from the database needs the FilamentDB plugin in FilaMan.",
    "Le choix dans la base demande le plugin FilamentDB dans FilaMan.",
    "从数据库选择需在 FilaMan 中安装 FilamentDB 插件。" },  // STR_DBPICK_FM_NO_PLUGIN
  { "Neues Filament aus der FilamentDB",
    "New filament from the FilamentDB",
    "Nouveau filament de la FilamentDB",
    "从 FilamentDB 新建耗材" },  // STR_TAGNEW_FROM_FDB
  { "Tag und Datenbank weichen ab",
    "Tag and database disagree",
    "Le tag et la base diffèrent",
    "标签与数据库不一致" },  // STR_TAGDB_TITLE
  { "Tag",
    "Tag",
    "Tag",
    "标签" },  // STR_TAGDB_TAG
  { "Datenbank",
    "Database",
    "Base",
    "数据库" },  // STR_TAGDB_DB
  { "Farbe",
    "Colour",
    "Couleur",
    "颜色" },  // STR_TAGDB_COLOR
  { "Düse min.",
    "Nozzle min",
    "Buse min.",
    "最低喷嘴温度" },  // STR_TAGDB_NOZZLE_MIN
  { "Düse max.",
    "Nozzle max",
    "Buse max.",
    "最高喷嘴温度" },  // STR_TAGDB_NOZZLE_MAX
  { "Gewicht",
    "Weight",
    "Poids",
    "重量" },  // STR_TAGDB_WEIGHT
  { "Tag behalten",
    "Keep the tag",
    "Garder le tag",
    "保留标签" },  // STR_TAGDB_KEEP
  { "Datenbank nehmen",
    "Use the database",
    "Prendre la base",
    "使用数据库" },  // STR_TAGDB_TAKE
  { "Aus dem Tag, ergänzt aus der Datenbank",
    "From the tag, completed from the database",
    "Du tag, complété par la base",
    "来自标签，并从数据库补全" },  // STR_TAGNEW_TAG_PLUS_DB
  { "Welche Leerspule?",
    "Which empty spool?",
    "Quelle bobine vide ?",
    "选择空料盘" },  // STR_DBPICK_CORE_TITLE
  { "Keine passt",
    "None of these",
    "Aucune ne convient",
    "均不匹配" },  // STR_DBPICK_CORE_NONE
  { "BamBuddy-Feld",
    "BamBuddy field",
    "Champ BamBuddy",
    "BamBuddy 字段" },  // STR_BB_DRIED_NATIVE
  { "Wird automatisch genutzt",
    "Used automatically",
    "Utilisé automatiquement",
    "自动使用" },  // STR_BB_DRIED_NATIVE_SUB
  { "Nur für BamBuddy ohne eigenes Feld",
    "Only for a BamBuddy without its own field",
    "Seulement pour un BamBuddy sans ce champ",
    "仅适用于无独立字段的 BamBuddy" },  // STR_BB_DRIED_OLDER_ONLY
  // A NIIMBOT printer and what it reports (services/niimbot.cpp)
  { "Das Gerät ist kein NIIMBOT-Drucker.",
    "The device is not a NIIMBOT printer.",
    "Pas une imprimante NIIMBOT.",
    "该设备不是 NIIMBOT 打印机。" },  // STR_PRN_ERR_NOT_NIIMBOT
  { "Der Deckel des Druckers ist offen.",
    "The printer's cover is open.",
    "Capot de l'imprimante ouvert.",
    "打印机盖未关闭。" },  // STR_PRN_ERR_COVER
  { "Kein Etikett im Drucker.",
    "No label in the printer.",
    "Aucune étiquette.",
    "打印机内无标签纸。" },  // STR_PRN_ERR_NO_PAPER
  { "Kein oder falsches Farbband im Drucker.",
    "No ribbon in the printer, or the wrong one.",
    "Ruban absent ou inadapté.",
    "打印机内无碳带或型号不匹配。" },  // STR_PRN_ERR_NO_RIBBON
  { "Der Drucker ist beschäftigt. Kurz warten, dann noch einmal.",
    "The printer is busy. Wait a moment, then try again.",
    "Imprimante occupée. Patientez un instant, puis réessayez.",
    "打印机正忙，请稍后重试。" },  // STR_PRN_ERR_BUSY
  { "Der Drucker meldet einen Fehler. Der Code steht im Log.",
    "The printer reports an error. The code is in the log.",
    "L'imprimante signale une erreur, code dans le journal.",
    "打印机报错，错误代码已记录至日志。" },  // STR_PRN_ERR_PRINTER
  { "Der Drucker ist ein anderes Modell als gewählt. Das Log nennt es.",
    "The printer is another model than the one picked. The log names it.",
    "Autre modèle que celui choisi. Le journal le nomme.",
    "打印机型号与所选不符，日志中有具体名称。" },  // STR_PRN_ERR_MODEL_MISMATCH
  { "Dieses NIIMBOT-Modell kennt die Waage noch nicht. Bitte die Kennung aus dem Log melden.",
    "The scale does not know this NIIMBOT model yet. Please report the id from the log.",
    "Modèle NIIMBOT encore inconnu de la balance. Merci de signaler l'identifiant du journal.",
    "暂不支持此 NIIMBOT 型号，请反馈日志中的 ID。" },  // STR_PRN_ERR_MODEL_UNKNOWN
  // Bluetooth switched on in the browser while the stack cannot start
  { "Bluetooth ist eingeschaltet, braucht aber einmal einen Neustart der Waage: Der Funk-Speicher wurde beim Start freigegeben.",
    "Bluetooth is on but needs one restart of the scale: its radio memory was released at boot.",
    "Bluetooth est activé mais la balance doit redémarrer une fois : la mémoire radio a été libérée au démarrage.",
    "蓝牙已开启，但需重启一次称重台（启动时已释放射频内存）。" },  // STR_W_P_RESTART_HINT
  { "Bluetooth braucht zuerst einen Neustart der Waage.",
    "Bluetooth needs a restart of the scale first.",
    "Bluetooth exige d'abord un redémarrage.",
    "蓝牙需先重启称重台。" },  // STR_PRN_ERR_BLE_RESTART
  // The printer page: the line under the print position strip when the label
  // fills the whole head
  { "Das Etikett füllt den ganzen Druckkopf, hier gibt es nichts zu verschieben.",
    "The label fills the whole print head, so there is nothing to move here.",
    "L'étiquette occupe toute la tête d'impression, il n'y a rien à décaler ici.",
    "标签已占满整个打印头，无需调整位置。" },  // STR_W_P_CAL_FILLS
  // The label editor in the browser: its tab, the template card, the preview card
  { "Etiketten",
    "Labels",
    "Étiquettes",
    "标签" },  // STR_W_NAV_LABEL
  { "Vorlage",
    "Template",
    "Modèle",
    "模板" },  // STR_W_L_TEMPLATE
  { "Anordnung",
    "Arrangement",
    "Disposition",
    "排版" },  // STR_W_L_ARRANGE
  { "Standard",
    "Standard",
    "Standard",
    "标准" },  // STR_W_L_P_STANDARD
  { "Kompakt",
    "Compact",
    "Compact",
    "紧凑" },  // STR_W_L_P_COMPACT
  { "QR groß",
    "Large QR",
    "Grand QR",
    "大 QR 码" },  // STR_W_L_P_BIG_QR
  { "Standard: Hersteller groß oben. Kompakt: Hersteller klein bei den Angaben, der QR-Code wird größer. QR groß: der Code über die ganze Höhe, der Text daneben. Material groß: das Material über ein Viertel der Höhe, der Code klein. Nur Text: kein Code, die Angaben groß, wo Platz ist in zwei Spalten. Nummer groß: die Spulennummer so groß, wie sie passt, der Rest darunter. Nummer rechts: dasselbe mit dem Rest links daneben in voller Höhe.",
    "Standard: the vendor large on top. Compact: the vendor small among the details, the QR code grows. Large QR: the code across the full height, the text beside it. Large material: the material across a quarter of the height, the code small. Text only: no code, the details large, in two columns where they fit. Large number: the spool number as large as it fits, the rest under it. Number right: the same with the rest to its left, at full height.",
    "Standard : le fabricant en grand en haut. Compact : le fabricant en petit parmi les infos, le code QR grandit. Grand QR : le code sur toute la hauteur, le texte à côté. Matière en grand : la matière sur un quart de la hauteur, le code en petit. Texte seul : sans code, les infos en grand, sur deux colonnes si elles tiennent. Grand numéro : le numéro de bobine aussi grand que possible, le reste en dessous. Numéro à droite : idem, le reste à gauche sur toute la hauteur.",
    "标准：品牌大字居顶。紧凑：品牌小字并入详情，QR 码放大。大 QR 码：QR 码占满高度，文字居侧。大材质：材质占四分之一高度，QR 码缩小。纯文本：无码，详情大字显示，空间允许时分两栏。大编号：料盘编号尽可能放大，其余信息居下。编号居右：同上，其余信息全高居左。" },  // STR_W_L_ARRANGE_HINT
  { "Felder",
    "Fields",
    "Champs",
    "字段" },  // STR_W_L_FIELDS
  { "Name",
    "Name",
    "Nom",
    "名称" },  // STR_W_L_F_NAME
  { "Datum",
    "Date",
    "Date",
    "日期" },  // STR_W_L_F_DATE
  { "QR-Code",
    "QR code",
    "Code QR",
    "QR 码" },  // STR_W_L_F_QR
  { "Projektname",
    "Project name",
    "Nom du projet",
    "项目名称" },  // STR_W_L_F_BRAND
  { "Optionen",
    "Options",
    "Options",
    "选项" },  // STR_W_L_OPTIONS
  { "Material ohne schwarzen Balken",
    "Material without the black band",
    "Matériau sans bandeau noir",
    "材质不带黑底条" },  // STR_W_L_O_PLAIN
  { "Immer das Anlagedatum",
    "Always the date added",
    "Toujours la date d'ajout",
    "始终显示添加日期" },  // STR_W_L_O_ADDED
  { "Sonst steht als Datum die erste Nutzung, wo der Server sie kennt, und sonst der Tag, an dem die Spule angelegt wurde.",
    "Otherwise the date is the first use where the server records it, else the day the spool was added.",
    "Sinon, la date est la première utilisation si le serveur la connaît, sinon le jour d'ajout de la bobine.",
    "否则若服务器记录了首次使用时间则显示该日期，否则显示料盘添加日期。" },  // STR_W_L_DATE_HINT
  { "Spule",
    "Spool",
    "Bobine",
    "料盘" },  // STR_W_L_SPOOL
  { "Beispieldaten: Seit dem Start hat die Waage noch keine Spule erkannt. Danach zeigt die Vorschau die zuletzt gescannte.",
    "Sample data: the scale has not recognised a spool since it started. After that the preview shows the last one scanned.",
    "Données d'exemple : la balance n'a reconnu aucune bobine depuis son démarrage. Ensuite, l'aperçu montre la dernière scannée.",
    "示例数据：开机后尚未识别到料盘，识别后此处将预览最后扫描的料盘。" },  // STR_W_L_SAMPLE
  { "Noch kein Drucker eingerichtet. Gerät, Modell und Etikett stehen unter",
    "No printer set up yet. Device, model and label stock are under",
    "Aucune imprimante configurée. Appareil, modèle et étiquette se règlent sous",
    "尚未设置打印机。设备、型号及标签纸设置位于" },  // STR_W_L_NO_PRINTER
  { "Etikett drucken",
    "Print label",
    "Imprimer l'étiquette",
    "打印标签" },  // STR_W_L_PRINT
  { "Druckt die Spule aus der Vorschau mit dieser Vorlage. Das Ergebnis erscheint auch auf der Waage.",
    "Prints the spool in the preview with this template. The result also shows on the scale.",
    "Imprime la bobine de l'aperçu avec ce modèle. Le résultat s'affiche aussi sur la balance.",
    "使用此模板打印预览中的料盘，结果也会显示在称重台上。" },  // STR_W_L_PRINT_HINT
  { "Letzter Etikettendruck",
    "Last label print",
    "Dernière étiquette imprimée",
    "上次标签打印" },  // STR_W_L_LAST_PRINT
  { "Vorschau nicht möglich: Druckermodell und Etikett prüfen.",
    "No preview: check the printer model and label stock.",
    "Aperçu impossible : vérifiez le modèle d'imprimante et l'étiquette.",
    "无法预览：请检查打印机型号与标签纸。" },  // STR_W_L_PREVIEW_FAIL
  { "(nicht mehr auf der Waage)",
    "(no longer on the scale)",
    "(plus sur la balance)",
    "（已离开秤盘）" },  // STR_W_L_OFF_PAD
  { "FilaMan hat das Etikett nicht gezeichnet.",
    "FilaMan did not draw the label.",
    "FilaMan n'a pas généré l'étiquette.",
    "FilaMan 未生成标签。" },  // STR_PRN_ERR_SERVER_LABEL
  { "Waagen-Layout",
    "Scale layout",
    "Modèle balance",
    "称重台布局" },  // STR_PRN_OWN_LAYOUT
  { "Quelle",
    "Source",
    "Source",
    "来源" },  // STR_W_L_SOURCE
  { "Waage",
    "Scale",
    "Balance",
    "称重台" },  // STR_W_L_SRC_SCALE
  { "Vorlagen aus dem Etiketten-Designer von FilaMan. Wählbar sind die in der Größe der eingelegten Rolle.",
    "Presets from FilaMan's label designer. The ones the size of the loaded roll can be chosen.",
    "Modèles du concepteur d'étiquettes de FilaMan. Seuls ceux à la taille du rouleau chargé peuvent être choisis.",
    "来自 FilaMan 标签设计器的预设，仅可选择与当前所装纸卷尺寸相符的预设。" },  // STR_W_L_SRC_HINT
  { "Vorlagen werden geladen ...",
    "Loading presets ...",
    "Chargement des modèles ...",
    "正在加载预设..." },  // STR_W_L_SRC_LOADING
  { "FilaMan hat die Vorlagen nicht geliefert, gleich ein neuer Versuch.",
    "FilaMan did not send the presets, trying again shortly.",
    "FilaMan n'a pas envoyé les modèles, nouvel essai sous peu.",
    "FilaMan 未返回预设，稍后将重试。" },  // STR_W_L_SRC_FAILED
  { "Dieses Etikett zeichnet FilaMan. Anordnung und Felder stehen im Etiketten-Designer von FilaMan.",
    "FilaMan draws this label. Arrangement and fields are set in FilaMan's label designer.",
    "FilaMan génère cette étiquette. Disposition et champs se règlent dans le concepteur d'étiquettes de FilaMan.",
    "此标签由 FilaMan 绘制，排版与字段均在 FilaMan 标签设计器中设置。" },  // STR_W_L_SRC_SERVER
  { "Etikett wird von FilaMan geladen ...",
    "Loading the label from FilaMan ...",
    "Chargement de l'étiquette depuis FilaMan ...",
    "正在从 FilaMan 加载标签..." },  // STR_W_L_PREVIEW_LOADING
  { "Für die Vorschau eine Spule auf die Waage legen.",
    "Put a spool on the scale for the preview.",
    "Posez une bobine sur la balance pour l'aperçu.",
    "请将料盘放上秤盘以预览。" },  // STR_W_L_SRC_NO_SPOOL

  // Auto-tare while the pad is empty
  { "Auto-Tara (leere Waage)", "Auto-tare (empty pad)", "Auto-tare (plateau vide)",
    "自动去皮（空秤盘）" },  // STR_BTN_AUTO_TARE
  { "Korrigiert langsames Wegdriften des Nullpunkts, solange die Waage leer ist.\n\nLiegt das Gewicht 3 Sekunden lang ruhig zwischen 0,5 und 5 g (positiv oder negativ), wird dieser Wert als neuer Nullpunkt gespeichert. Sobald ein Tag erkannt wird oder eine Spule aufliegt, passiert nichts. Mehr als 5 g werden nie ausgeglichen, und zwischen zwei Korrekturen vergeht mindestens eine Minute.\n\nDie TARE-Taste funktioniert weiterhin wie gewohnt.",
    "Corrects slow drift of the zero point while the pad is empty.\n\nIf the weight sits steady between 0.5 and 5 g (positive or negative) for 3 seconds, that value is stored as the new zero. Nothing happens while a tag is detected or a spool is on the pad. More than 5 g is never corrected, and at least a minute passes between two corrections.\n\nThe TARE button still works as before.",
    "Corrige la dérive lente du zéro tant que le plateau est vide.\n\nSi le poids reste stable entre 0,5 et 5 g (positif ou négatif) pendant 3 secondes, cette valeur devient le nouveau zéro. Rien ne se passe tant qu'un tag est détecté ou qu'une bobine est posée. Plus de 5 g n'est jamais corrigé, et il s'écoule au moins une minute entre deux corrections.\n\nLe bouton TARE fonctionne toujours comme avant.",
    "在秤盘空载时自动修正零点的缓慢漂移。\n\n若重量在 0.5 至 5 g（正负均可）之间稳定保持 3 秒，该数值将被存为新零点。检测到标签或秤盘放有料盘时不会触发。超过 5 g 绝不修正，且两次修正之间至少间隔 1 分钟。\n\n去皮（TARE）按钮功能保持不变。" },  // STR_BTN_AUTO_TARE_INFO
  // The mark on the TARE button while auto-tare is on
  { "A", "A", "A", "A" },  // STR_TARE_AUTO_MARK
  // The bag weight at 0: the menu row says so, and the weight popup leaves
  // out its bag switch
  { "Aus - kein Beutel", "Off - no bag", "Sans sachet", "关闭 - 无包装袋" },  // STR_BAG_OFF_SUB
  // The empty spool weight the netto subtracts, shown in the live zone
  // without a bag
  { "Spule", "Spool", "Bobine", "料盘" },  // STR_LBL_SPOOL_TARE_CAP
  // Behind the help circle on the bag screen: what the value does to the
  // main screen and the weight popup, and that crossing 0 needs a restart
  { "Für Spulen, die im Vakuumbeutel auf der Waage liegen. Der Wert ist das Gewicht des leeren Beutels samt Silikagelpack und wird von jeder Messung abgezogen.\n\nMit Beutel (Wert über 0 g): Der Hauptschirm zeigt vier Zeilen: Waage minus Spule, Diff, Gesamt und das Gewicht ohne Beutel mit eigener Diff. Beim Übertragen fragt die Waage, ob die Spule mit oder ohne Beutel aufliegt.\n\nOhne Beutel (0 g): Der Hauptschirm zeigt Waage minus Spule, Diff, Gesamt und das Spulengewicht, größer und mit mehr Platz. Übertragen geht mit einem Knopf, ohne Rückfrage.\n\nAb Werk steht hier 0 g. Ein neuer Wert wirkt sofort, auch der Wechsel zwischen 0 g und einem Wert: Der Hauptschirm stellt dann seine Zeilen um.",
    "For spools that sit on the scale in a vacuum bag. The value is the weight of the empty bag with its silica gel pack, and it is subtracted from every reading.\n\nWith a bag (value above 0 g): the main screen shows four lines: scale minus spool, diff, total and the weight without the bag with a diff of its own. When sending the weight, the scale asks whether the spool is on the pad with or without its bag.\n\nWithout a bag (0 g): the main screen shows scale minus spool, diff, total and the spool weight, larger and with more room. Sending takes one button, no question asked.\n\nThe factory setting is 0 g. A new value takes effect at once, the change between 0 g and a value too: the main screen then rearranges its lines.",
    "Pour les bobines pesées dans un sachet sous vide. La valeur est le poids du sachet vide avec son gel de silice, soustrait de chaque mesure.\n\nAvec sachet (plus de 0 g) : l'écran principal affiche quatre lignes : balance moins bobine, écart, total et le poids sans sachet avec son propre écart. À l'envoi du poids, la balance demande si la bobine est posée avec ou sans sachet.\n\nSans sachet (0 g) : l'écran principal affiche balance moins bobine, écart, total et le poids de la bobine, en plus grand. L'envoi se fait d'un seul bouton, sans question.\n\nRéglage d'usine : 0 g. Une nouvelle valeur agit aussitôt, le passage entre 0 g et une valeur aussi : l'écran principal réorganise alors ses lignes.",
    "适用于装在真空袋中称重的料盘。设定值为空包装袋加干燥剂包的总重，每次读数都会自动减去该重量。\n\n设包装袋重（大于 0 g）：主屏显示四行：总重减空盘、差值、总重，以及不含袋净重及其差值。上传重量时，秤会询问料盘是否带袋称重。\n\n无包装袋（0 g）：主屏显示总重减空盘、差值、总重及料盘重量，字号更大、空间更宽裕。一键直接上传，无需确认。\n\n出厂默认为 0 g。新数值立即生效，在 0 g 与非零值之间切换时，主屏会自动调整显示布局。" },  // STR_BAG_HELP_TEXT
  { "In %s anzeigen",
    "Show in %s",
    "Afficher dans %s",
    "在 %s 中显示" },  // STR_W_C_EMBED
  { "Mit dem Plugin „SpoolmanScale“ erscheint diese Weboberfläche in der Navigation von FilaMan und folgt dessen Hell- oder Dunkel-Modus.",
    "With the “SpoolmanScale” plugin, this web interface appears in FilaMan's navigation and follows its light or dark mode.",
    "Avec le plugin « SpoolmanScale », cette interface web apparaît dans la navigation de FilaMan et suit son mode clair ou sombre.",
    "安装“SpoolmanScale”插件后，此 Web 界面将显示在 FilaMan 的导航栏中，并自动同步其浅色或深色模式。" },  // STR_W_EMBED_FM_INTRO
  { "Plugin herunterladen",
    "Download the plugin",
    "Télécharger le plugin",
    "下载插件" },  // STR_W_EMBED_FM_DOWNLOAD
  { "In FilaMan unter <b>Admin-Bereich › Plugins</b> hochladen",
    "Upload it in FilaMan under <b>Admin Panel › Plugins</b>",
    "Le téléverser dans FilaMan sous <b>Espace admin › Plugins</b>",
    "在 FilaMan 的 <b>Admin Panel › Plugins</b> 中上传该插件" },  // STR_W_EMBED_FM_UPLOAD
  { "%s im Browser mit genau dieser Adresse öffnen",
    "Open %s in the browser with exactly this address",
    "Ouvrez %s dans le navigateur avec exactement cette adresse",
    "请在浏览器中使用此精确地址打开 %s" },  // STR_W_EMBED_OPEN_AS
  { "BamBuddy zeigt diese Weboberfläche ohne Plugin in seiner Seitenleiste und gibt seinen Hell- oder Dunkel-Modus weiter.",
    "BamBuddy shows this web interface in its sidebar without a plugin and passes on its light or dark mode.",
    "BamBuddy affiche cette interface web dans sa barre latérale, sans plugin, et lui transmet son mode clair ou sombre.",
    "BamBuddy 无需安装插件即可在侧边栏中嵌入显示此 Web 界面，并自动同步浅色或深色模式。" },  // STR_W_EMBED_BB_INTRO
  { "In BamBuddy unter <b>Einstellungen › Allgemein › Seitenleiste</b> einen Link anlegen",
    "In BamBuddy, add a link under <b>Settings › General › Sidebar</b>",
    "Dans BamBuddy, ajoutez un lien sous <b>Paramètres › Général › Barre latérale</b>",
    "在 BamBuddy 中，前往 <b>Settings › General › Sidebar</b> 添加链接" },  // STR_W_EMBED_BB_STEP1
  { "Als URL die Adresse der Waage eintragen, „In neuem Tab öffnen“ aus lassen",
    "Enter the scale's address as the URL and leave “Open in new tab” off",
    "Saisissez l'adresse de la balance comme URL et laissez « Ouvrir dans un nouvel onglet » désactivé",
    "将电子秤地址填入 URL，并保持“Open in new tab”为关闭状态" },  // STR_W_EMBED_BB_STEP2
  { "Der Name bleibt gültig, wenn der Router der Waage eine neue IP gibt, manche Android-Geräte lösen ihn aber nicht auf. Die IP geht überall, dann im Router fest vergeben.",
    "The name keeps working when the router gives the scale a new IP, but some Android devices do not resolve it. The IP works everywhere; then give it a fixed lease in the router.",
    "Le nom reste valable si le routeur attribue une nouvelle IP à la balance, mais certains appareils Android ne le résolvent pas. L'IP fonctionne partout : réservez-la alors dans le routeur.",
    "路由器重新分配 IP 后主机名依然有效，但部分 Android 设备无法解析。使用 IP 地址在所有设备上均可访问，建议在路由器中为其分配静态 IP。" },  // STR_W_EMBED_BB_IP
  { "Im Router eine feste IP für die Waage vergeben, sonst führt der Link nach einer neuen IP ins Leere.",
    "Give the scale a fixed IP in the router, otherwise the link leads nowhere once it gets a new one.",
    "Attribuez une IP fixe à la balance dans le routeur, sinon le lien ne mène nulle part après un changement d'IP.",
    "请在路由器中为电子秤设置固定 IP，否则 IP 变更后该链接将失效。" },  // STR_W_EMBED_BB_FIXIP
  { "Unter einer anderen Adresse (Name statt IP, Proxy) zeigt der Browser die Waage dort nicht an.",
    "Under any other address (a name instead of the IP, a proxy) the browser does not show the scale there.",
    "Sous une autre adresse (un nom au lieu de l'IP, un proxy), le navigateur n'y affiche pas la balance.",
    "若通过其他地址（如使用主机名而非 IP，或经过反向代理）访问，浏览器将无法在该页面内嵌入显示电子秤界面。" },  // STR_W_EMBED_NOTE
  { "Oben steht eine https-Adresse. Eine https-Seite darf die Waage, die nur http spricht, nicht einbetten. Zum Einbetten das Backend oben mit http eintragen und so öffnen.",
    "The address above is https. An https page may not embed the scale, which only speaks http. To embed it, enter the backend above with http and open it that way.",
    "L'adresse ci-dessus est en https. Une page https ne peut pas intégrer la balance, qui ne parle que http. Pour l'intégrer, saisissez le backend ci-dessus en http et ouvrez-le ainsi.",
    "上方地址为 https。由于电子秤仅支持 http，https 页面无法直接嵌入显示。如需嵌入，请在上方将后端地址改为 http 并以此方式打开。" },  // STR_W_EMBED_HTTPS
  { "Öffnen",
    "Open",
    "Ouvrir",
    "打开" },  // STR_W_OPEN
  { "Kopieren fehlgeschlagen",
    "Copy failed",
    "Copie impossible",
    "复制失败" },  // STR_W_COPY_FAILED
  { "Spoolman hinter BamBuddy ist von der Waage aus nicht erreichbar:\n%s",
    "Spoolman behind BamBuddy cannot be reached from the scale:\n%s",
    "Spoolman derrière BamBuddy est injoignable depuis la balance :\n%s",
    "电子秤无法访问 BamBuddy 后端的 Spoolman：\n%s" },  // STR_DBPICK_SM_UNREACHABLE
  { "DD.MM.YYYY",
    "DD.MM.YYYY",
    "DD.MM.YYYY",
    "DD.MM.YYYY" },  // STR_DATE_FMT_DMY
  { "YYYY-MM-DD",
    "YYYY-MM-DD",
    "YYYY-MM-DD",
    "YYYY-MM-DD" },  // STR_DATE_FMT_ISO
  { "MM/DD/YYYY",
    "MM/DD/YYYY",
    "MM/DD/YYYY",
    "MM/DD/YYYY" },  // STR_DATE_FMT_US
  { "passt gedreht", "fits rotated", "compatible après rotation", "旋转后适配" },  // STR_W_L_SRC_ROTATED
  // Releasing the tags after a spool is archived
  { "Tag freigeben?\nAlle Tags werden von der Spule getrennt.",
    "Release the tag?\nAll tags of this spool are unlinked.",
    "Libérer le tag ?\nTous les tags sont dissociés.",
    "释放此标签？\n该料盘绑定的所有标签都将被解绑。" },  // STR_FREE_TAG_ASK
  { "Der aufliegende Tag wird gelöscht.",
    "The tag on the reader is erased.",
    "Le tag posé est effacé.",
    "读卡器上的标签数据将被擦除。" },  // STR_FREE_TAG_ERASE_LINE
  { "Freigeben", "Release", "Libérer", "释放" },  // STR_BTN_FREE_TAG
  // Label editor: more arrangements, upright labels, a line budget
  { "Material groß", "Large material",
    "Matière en grand",
    "大号材质" },  // STR_W_L_P_MATERIAL_BIG
  { "Nur Text", "Text only",
    "Texte seul",
    "仅文本" },  // STR_W_L_P_TEXT_ONLY
  { "Ausrichtung", "Orientation",
    "Orientation",
    "方向" },  // STR_W_L_ORIENT
  { "Quer", "Landscape",
    "Paysage",
    "横向" },  // STR_W_L_FLAT
  { "Hochkant", "Portrait",
    "Portrait",
    "纵向" },  // STR_W_L_UPRIGHT
  { "Zeilen: %d von %d", "Lines: %d of %d",
    "Lignes : %d sur %d",
    "行数：%d / %d" },  // STR_W_L_CAP
  { "Mehr Zeilen passen auf dieses Etikett nicht.", "No more lines fit on this label.",
    "Aucune ligne de plus ne tient sur cette étiquette.",
    "此标签已无法容纳更多行。" },  // STR_W_L_CAP_FULL
  { "Die letzten Zeilen passen nicht und fallen weg.", "The last lines do not fit and are left off.",
    "Les dernières lignes ne tiennent pas et sont omises.",
    "末尾超出部分将无法打印并被省略。" },  // STR_W_L_CAP_OVER
  // Label editor: more fields, an own line
  { "Leer", "Empty",
    "Vide",
    "空盘" },  // STR_LBL_L_EMPTY
  { "Netto", "Net",
    "Net",
    "净重" },  // STR_LBL_L_NET
  { "Düse", "Nozzle",
    "Buse",
    "喷嘴" },  // STR_LBL_L_NOZZLE
  { "Düse/Bett", "Nozzle/bed",
    "Buse/plat.",
    "喷嘴/热床" },  // STR_LBL_L_TEMPS
  { "Lager", "Stored",
    "Lieu",
    "存放" },  // STR_LBL_L_STORED
  { "Getrocknet", "Dried",
    "Séchée",
    "已烘干" },  // STR_LBL_L_DRIED
  { "Leergewicht", "Empty weight",
    "Poids à vide",
    "空盘重量" },  // STR_W_L_F_SPOOL_W
  { "Nettogewicht", "Net weight",
    "Poids net",
    "净重" },  // STR_W_L_F_NET_W
  { "Temperaturen", "Temperatures",
    "Températures",
    "温度" },  // STR_W_L_F_TEMPS
  { "Lagerort", "Location",
    "Emplacement",
    "存放位置" },  // STR_W_L_F_LOCATION
  { "Trocknungsdatum", "Drying date",
    "Date de séchage",
    "烘干日期" },  // STR_W_L_F_DRIED
  { "Eigene Zeile", "Own line",
    "Ligne libre",
    "自定义行" },  // STR_W_L_F_TEXT
  { "Eigene Zeile: höchstens 40 Zeichen.", "Own line: 40 characters at most.",
    "Ligne libre : 40 caractères au plus.",
    "自定义行：最多 40 个字符。" },  // STR_W_L_TEXT_HINT
  { "Lagerort und Trocknungsdatum ändern sich, das Etikett nicht. Temperaturen kennt nicht jedes Backend.", "Location and drying date change, the label does not. Not every backend knows temperatures.",
    "L'emplacement et la date de séchage changent, l'étiquette non. Tous les backends ne connaissent pas les températures.",
    "存放位置和烘干日期会随之更新，标签本身不会变。并非所有后端都支持温度信息。" },  // STR_W_L_CHANGE_HINT
  // Label editor: the filament's label
  { "Etikett für", "Label for",
    "Étiquette pour",
    "标签类型" },  // STR_W_L_KIND
  { "Spule", "Spool",
    "Bobine",
    "料盘" },  // STR_W_L_KIND_SPOOL
  { "Filament", "Filament",
    "Filament",
    "耗材" },  // STR_W_L_KIND_FILAMENT
  { "Am Gerät wählst du die Art im Druckfenster, ohne Druckfenster kommt das der Spule.", "On the scale the print sheet picks the kind; without the sheet the spool's prints.",
    "Sur la balance, la fenêtre d'impression choisit le type ; sans elle, c'est celle de la bobine.",
    "在称重台上可通过打印弹窗选择标签类型；若关闭弹窗，则默认打印料盘标签。" },  // STR_W_L_KIND_HINT
  { "Dieses Backend hat keine Filamentseite: das Filament-Etikett kommt ohne Code.", "This backend has no filament page: the filament label prints without a code.",
    "Ce backend n'a pas de page filament : l'étiquette du filament s'imprime sans code.",
    "当前后端无耗材页面：耗材标签将不带二维码打印。" },  // STR_W_L_FIL_NO_PAGE
  // The print sheet on the scale
  { "Drucken", "Print",
    "Imprimer",
    "打印" },  // STR_PS_PRINT
  { "Vor dem Druck zeigen", "Show before printing",
    "Aperçu d'abord",
    "打印前预览" },  // STR_PS_ASK
  { "Vorschau und Einstellungen", "Preview and settings",
    "Aperçu et réglages",
    "预览与设置" },  // STR_PS_ASK_SUB
  { "Layout aus FilaMan", "Layout from FilaMan",
    "Mise en page FilaMan",
    "FilaMan 布局" },  // STR_PS_SERVER
  { "Im Browser unter Etiketten", "In the browser, under Labels",
    "Navigateur, Étiquettes",
    "在浏览器“标签”页设置" },  // STR_PS_SERVER_SUB
  { "Felder, eigene Zeile und FilaMan-Vorlagen stellst du im Browser ein:", "Fields, the own line and FilaMan presets are set in the browser:",
    "Champs, ligne libre et modèles FilaMan : dans le navigateur",
    "字段、自定义行及 FilaMan 预设请在浏览器中设置：" },  // STR_PS_MORE_WEB
  // A fact on a printed label, caption and value on one line
  { "%s: %s", "%s: %s", "%s : %s", "%s：%s" },  // STR_LBL_FACT_FMT
  // Label editor: the drying, and the switches that print nothing
  { "Trocknen",              "Dry",                  "Séchage",                "烘干" },  // STR_LBL_L_DRYING
  { "Trocknen (°C, h)",      "Drying (°C, h)",       "Séchage (°C, h)",        "烘干 (°C, h)" },  // STR_W_L_F_DRYING
  { "bei dieser Spule leer", "empty for this spool", "vide pour cette bobine", "此料盘未填写" },  // STR_W_L_GAP_SPOOL
  { "%s führt es nicht",     "%s does not keep it",  "%s ne le gère pas",      "%s 不支持此项" },  // STR_W_L_GAP_BACKEND
  // Printer page: how a model prints, and the recommended printers
  { "Druckt per Thermodirekt, ohne Farbband.", "Prints direct thermal, without a ribbon.",
    "Impression thermique directe, sans ruban.",
    "采用热敏直印，无需碳带。" },  // STR_W_P_METHOD_DIRECT
  { "Druckt per Thermotransfer mit Farbband: Wärme färbt das Etikett nicht.", "Prints by thermal transfer with a ribbon: heat does not colour the label.",
    "Impression par transfert thermique à ruban : la chaleur ne colore pas l'étiquette.",
    "采用热转印配合碳带打印：受热不会使标签变色。" },  // STR_W_P_METHOD_RIBBON
  { "Empfohlene Drucker", "Recommended printers",
    "Imprimantes recommandées",
    "推荐打印机" },  // STR_W_P_SHOP_TITLE
  { "Welche Drucker wir selbst testen und welche Etiketten dazu passen.", "The printers we test ourselves and the labels that go with them.",
    "Les imprimantes que nous testons nous-mêmes et les étiquettes qui leur conviennent.",
    "我们亲自测试过的打印机及适配标签。" },  // STR_W_P_SHOP_HINT
  // Bluetooth screen: the way to the recommended printers
  { "Noch kein Drucker?", "No printer yet?",
    "Pas encore d'imprimante ?",
    "还没有打印机？" },  // STR_BT_REC_NONE
  { "Welche passen: QR-Code zum Handbuch", "Which ones fit: QR code to the manual",
    "Lesquelles conviennent : QR code du manuel",
    "适配机型：扫码查看手册" },  // STR_BT_REC_NONE_SUB
  { "Empfohlene Drucker", "Recommended printers",
    "Imprimantes recommandées",
    "推荐打印机" },  // STR_BT_REC_OTHER
  { "Von uns getestet: QR-Code zum Handbuch", "Tested by us: QR code to the manual",
    "Testées par nous : QR code du manuel",
    "实测推荐：扫码查看手册" },  // STR_BT_REC_OTHER_SUB
  { "Etiketten nachkaufen", "Buy more labels",
    "Racheter des étiquettes",
    "购买标签纸" },  // STR_BT_REC_LABELS
  { "Etiketten und Farbband", "Labels and ribbon",
    "Étiquettes et ruban",
    "标签与碳带" },  // STR_BT_REC_RIBBON
  { "Passende Rollen: QR-Code zum Handbuch", "Rolls that fit: QR code to the manual",
    "Rouleaux adaptés : QR code du manuel",
    "适配耗材：扫码查看手册" },  // STR_BT_REC_SUPPLY_SUB
  // Printer page: the box worded for the printer at hand
  { "Zwei Drucker testen wir selbst mit jeder Version: Phomemo M220 und NIIMBOT M2. Welcher zu dir passt, zeigt der Vergleich im Handbuch.", "We test two printers ourselves with every release: the Phomemo M220 and the NIIMBOT M2. The comparison in the manual shows which one suits you.",
    "Nous testons nous-mêmes deux imprimantes à chaque version : la Phomemo M220 et la NIIMBOT M2. La comparaison dans le manuel montre laquelle vous convient.",
    "每个版本发布时，我们都会亲自测试两款打印机：Phomemo M220 和 NIIMBOT M2。手册中的对比可帮你选择适合的机型。" },  // STR_W_P_REC_NONE_TEXT
  { "Drucker vergleichen", "Compare printers",
    "Comparer les imprimantes",
    "对比打印机" },  // STR_W_P_REC_NONE_BTN
  { "Neue Etikettenfunktionen bauen und testen wir zuerst auf M220 und M2. Was sie unterscheidet, steht im Handbuch.", "We build and test new label features on the M220 and the M2 first. What sets them apart is in the manual.",
    "Nous développons et testons les nouvelles fonctions d'étiquette d'abord sur la M220 et la M2. Ce qui les distingue est dans le manuel.",
    "所有新标签功能都会优先在 M220 和 M2 上开发与测试。两者的区别详见手册。" },  // STR_W_P_REC_OTHER_TEXT
  { "Zum Vergleich", "See the comparison",
    "Voir la comparaison",
    "查看对比" },  // STR_W_P_REC_OTHER_BTN
  { "Passende Rollen für deinen M220, in 40 x 30 und 50 x 30 mm.", "Rolls that fit your M220, in 40 x 30 and 50 x 30 mm.",
    "Rouleaux adaptés à votre M220, en 40 x 30 et 50 x 30 mm.",
    "适配 M220 的标签纸，提供 40 x 30 和 50 x 30 mm 规格。" },  // STR_W_P_REC_M220_TEXT
  { "Zu den Etiketten", "To the labels",
    "Voir les étiquettes",
    "查看标签纸" },  // STR_W_P_REC_LABELS_BTN
  { "Passende Rollen und Farbband für deinen M2.", "Rolls and ribbon that fit your M2.",
    "Rouleaux et ruban adaptés à votre M2.",
    "适配 M2 的标签纸和色带。" },  // STR_W_P_REC_M2_TEXT
  { "Zu Etiketten und Farbband", "To labels and ribbon",
    "Voir étiquettes et ruban",
    "查看标签纸和色带" },  // STR_W_P_REC_RIBBON_BTN
  { "Anderer Tag auf dem Leser - nicht gelöscht", "A different tag is on the reader - not erased",
    "Autre tag sur le lecteur - rien effacé",
    "读卡器上为其他标签 - 未擦除" },  // STR_TW_ERR_OTHER_TAG
  { "Empfohlen", "Recommended",
    "Recommandée",
    "推荐" },  // STR_PRN_TAG_RECOMMENDED
  { "experimentell", "experimental",
    "expérimentale",
    "实验性" },  // STR_PRN_TAG_EXPERIMENTAL
  { "Auch in Extra-Feld", "Also in extra field",
    "Aussi dans un champ",
    "同步写入额外字段" },  // STR_TAG_COMP
  { "Nicht jedes Tool kennt die nativen Tags von Spoolman. Hier schreibt die Waage beim Verknüpfen zusätzlich in ein Extra-Feld und legt es an, falls es fehlt.\n\nextra.tag: die UUID einer Bambu-Spule, für OpenSpoolman. Andere Tags betrifft das nicht.\nextra.nfc_id: die UUID einer Bambu-Spule, bei anderen Tags die Chip-UID.\n\nBeim Auflegen füllt die Waage nur ein leeres Feld. Geleert wird es erst, wenn alle Tags der Spule gelöst werden oder der Tag, dessen UID darin steht.",
    "Not every tool knows Spoolman's native tags. With this, the scale also writes into an extra field when linking, and creates the field if it is missing.\n\nextra.tag: the UUID of a Bambu spool, for OpenSpoolman. Other tags are not affected.\nextra.nfc_id: the UUID of a Bambu spool, the chip UID for other tags.\n\nWhen a spool is placed, the scale only fills an empty field. It is cleared only when all of the spool's tags are unlinked, or the tag whose UID it holds.",
    "Certains outils ignorent les tags natifs de Spoolman. La balance écrit alors aussi dans un champ supplémentaire lors d'une liaison et le crée s'il manque.\n\nextra.tag : l'UUID d'une bobine Bambu, pour OpenSpoolman. Rien pour les autres tags.\nextra.nfc_id : l'UUID d'une bobine Bambu, sinon l'UID de la puce.\n\nUne bobine posée ne remplit qu'un champ vide. Il n'est vidé que si tous ses tags sont dissociés, ou le tag dont il contient l'UID.",
    "并非所有工具都支持 Spoolman 原生标签。开启后，绑定标签时秤还会同步写入额外字段（若不存在则自动创建）。\n\nextra.tag：Bambu 料盘的 UUID，用于 OpenSpoolman，不影响其他标签。\nextra.nfc_id：Bambu 料盘的 UUID，或其他标签的芯片 UID。\n\n放上料盘时，仅当该字段为空才会填入；仅当该料盘所有标签均已解绑，或记录其 UID 的标签解绑时才会清空。" },  // STR_TAG_COMP_INFO
  { "Aus", "Off", "Désactivé", "关闭" },  // STR_TAG_COMP_OFF
  { "Nur die nativen Tags", "Native tags only",
    "Tags natifs uniquement",
    "仅原生标签" },  // STR_TAG_COMP_OFF_SUB
  { "extra.tag", "extra.tag", "extra.tag", "extra.tag" },  // STR_TAG_COMP_TAG
  { "Bambu-UUID, für OpenSpoolman", "Bambu UUID, for OpenSpoolman",
    "UUID Bambu, pour OpenSpoolman",
    "Bambu UUID，用于 OpenSpoolman" },  // STR_TAG_COMP_TAG_SUB
  { "extra.nfc_id", "extra.nfc_id", "extra.nfc_id", "extra.nfc_id" },  // STR_TAG_COMP_NFCID
  { "Bambu-UUID oder Chip-UID", "Bambu UUID or chip UID",
    "UUID Bambu ou UID de puce",
    "Bambu UUID 或芯片 UID" },  // STR_TAG_COMP_NFCID_SUB
  // Printer page: only BLE printers, and the way to what a printer needs
  { "Die Waage spricht nur Bluetooth Low Energy. Drucker mit klassischem Bluetooth, etwa Brother P-touch, kann sie nicht erreichen.",
    "The scale speaks Bluetooth Low Energy only. Printers on Classic Bluetooth, such as Brother P-touch, are out of its reach.",
    "La balance ne parle que le Bluetooth Low Energy. Les imprimantes en Bluetooth classique, comme les Brother P-touch, lui restent inaccessibles.",
    "本秤仅支持低功耗蓝牙（BLE），无法连接 Brother P-touch 等经典蓝牙打印机。" },  // STR_W_P_BLE_ONLY
  { "Was ein Drucker können muss", "What a printer needs",
    "Ce qu'une imprimante doit savoir faire",
    "打印机兼容性要求" },  // STR_W_P_NEEDS_LINK
  { "Neustart nötig", "Restart needed",
    "Redémarrage requis",
    "需要重启" },  // STR_W_P_RESTART_NEEDED
  { "Drucker einschalten, dann suchen.", "Switch the printer on, then scan.",
    "Allumez l'imprimante, puis lancez la recherche.",
    "请先打开打印机电源，再进行扫描。" },  // STR_W_P_EMPTY_HINT
  { "Wähle deinen Drucker aus der Liste unten.", "Pick yours from the list below.",
    "Choisissez la vôtre dans la liste ci-dessous.",
    "请从下方列表中选择你的打印机。" },  // STR_W_P_PICK_HINT
  { "Drucker wechseln", "Change printer",
    "Changer d'imprimante",
    "更换打印机" },  // STR_W_P_CHANGE
  { "Farbband", "ribbon",
    "ruban",
    "色带" },  // STR_W_P_SPEC_RIBBON
  // ── The card for a spool the inventory does not know ──
  { "Bei unbekannter Spule fragen",
    "Ask about unknown spools",
    "Demander si bobine inconnue",
    "未知料盘提示" },  // STR_UNK_ASK
  { "Beim Auflegen",
    "When one is put down",
    "À la pose",
    "放上料盘时询问" },  // STR_UNK_ASK_SUB
  { "An: Legst du eine Spule auf, die das Inventar noch nicht kennt, schlägt die Waage den nächsten Schritt vor - eine passende Spule ohne Tag verknüpfen oder eine neue aus dem Tag anlegen. \"Nur wiegen\" schließt die Frage, bis die Spule wieder heruntergenommen wird.\n\nAus: Es wechseln nur die beiden Knöpfe auf dem Hauptscreen, wie bisher.",
    "On: when you put down a spool the inventory does not know yet, the scale suggests the next step - link a matching spool without a tag, or create a new one from the tag. \"Just weigh\" closes the question until the spool is taken off again.\n\nOff: only the two buttons on the main screen change, as before.",
    "Activé : quand vous posez une bobine que l'inventaire ne connaît pas encore, la balance propose l'étape suivante - lier une bobine correspondante sans tag, ou en créer une nouvelle depuis le tag. « Juste peser » ferme la question jusqu'à ce que la bobine soit retirée.\n\nDésactivé : seuls les deux boutons de l'écran principal changent.",
    "开启：放上库存中尚无记录的料盘时，秤会建议下一步操作——绑定匹配的未绑定标签料盘，或根据标签新建料盘。点击\"仅称重\"可关闭提示，直至取下料盘。\n\n关闭：与之前相同，仅更改主屏幕上的两个按钮。" },  // STR_UNK_ASK_INFO
  { "Vorschlag: diese Spule ohne Tag",
    "Suggestion: this spool without a tag",
    "Suggestion : cette bobine sans tag",
    "建议：绑定此无标签料盘" },  // STR_UNK_SUGGEST_ONE
  { "Vorschlag: %d Spulen ohne Tag passen",
    "Suggestion: %d spools without a tag match",
    "Suggestion : %d bobines sans tag conviennent",
    "建议：匹配 %d 个无标签料盘" },  // STR_UNK_SUGGEST_MANY
  { "Vorschlag: neu aus dem Tag",
    "Suggestion: new from the tag",
    "Suggestion : nouvelle depuis le tag",
    "建议：根据标签新建" },  // STR_UNK_SUGGEST_NEW
  { "%s im Bestand, passt zur Waage",
    "%s on file, matches the scale",
    "%s en stock, comme la balance",
    "库存有 %s，重量匹配" },  // STR_UNK_STORED_HIT
  { "%s im Bestand",
    "%s on file",
    "%s en stock",
    "库存有 %s" },  // STR_UNK_STORED
  { "Noch keine Spule davon im Bestand",
    "No spool of it in the inventory yet",
    "Pas encore dans l'inventaire",
    "库存中暂无此料盘" },  // STR_UNK_NONE_LINE
  { "Neue Spule aus den Daten des Tags",
    "A new spool from the tag's data",
    "Nouvelle bobine selon le tag",
    "根据标签数据新建料盘" },  // STR_UNK_NONE_SUB
  { "+%d weitere",
    "+%d more",
    "+%d autres",
    "另有 %d 个" },  // STR_UNK_MORE
  { "Alle zeigen",
    "Show all",
    "Tout voir",
    "显示全部" },  // STR_UNK_BTN_ALL
  { "Andere Wege",
    "Other ways",
    "Autres choix",
    "其他方式" },  // STR_UNK_BTN_OTHER
  { "Nur wiegen",
    "Just weigh",
    "Juste peser",
    "仅称重" },  // STR_UNK_BTN_WEIGH
  { "Kopie",
    "Copy",
    "Copie",
    "复制" },  // STR_UNK_TILE_COPY
  { "%.0f g netto",
    "%.0f g net",
    "%.0f g net",
    "净重 %.0f g" },  // STR_UNK_NET
  { "%.0f g auf der Waage",
    "%.0f g on the scale",
    "%.0f g sur la balance",
    "秤上重 %.0f g" },  // STR_UNK_GROSS
  { "UID %s",
    "UID %s",
    "UID %s",
    "UID %s" },  // STR_UNK_UID
  { "?",
    "?",
    "?",
    "?" },  // STR_UNK_NO_COLOR
  // ── What a spool created off the pad starts with ──
  { "%.0f von %d g",
    "%.0f of %d g",
    "%.0f sur %d g",
    "%.0f / %d g" },  // STR_TAGNEW_W_OF
  { "voll: %.0f g",
    "full: %.0f g",
    "pleine : %.0f g",
    "满盘: %.0f g" },  // STR_TAGNEW_W_FULL
  { "nicht gewogen, voll: %d g",
    "not weighed, full: %d g",
    "non pesée, pleine : %d g",
    "未称重，满盘: %d g" },  // STR_TAGNEW_W_NOT
  { "Leerspule unbekannt, voll: %d g",
    "empty spool unknown, full: %d g",
    "bobine vide inconnue, pleine : %d g",
    "空盘未知，满盘: %d g" },  // STR_TAGNEW_W_NO_TARE
  { "zu schwer: %.0f g, voll: %d g",
    "too heavy: %.0f g, full: %d g",
    "trop lourde : %.0f g, pleine : %d g",
    "超重: %.0f g，满盘: %d g" },  // STR_TAGNEW_W_OVER
  { "zu schwer: %.0f g, Leerspule %d g prüfen",
    "too heavy: %.0f g, check empty spool %d g",
    "trop lourde : %.0f g, vérifier vide %d g",
    "超重: %.0f g，请核对空盘 %d g" },  // STR_TAGNEW_W_OVER_TARE
  { "%s | leer %.0f g",
    "%s | empty %.0f g",
    "%s | vide %.0f g",
    "%s | 空盘 %.0f g" },  // STR_COPY_CARD_TARE
  // Printing on the PC through FilaMan
  { "Am PC drucken",
    "Print on the PC",
    "Imprimer sur le PC",
    "电脑端打印" },  // STR_PCP_TITLE
  { "Über FilaMan. Dazu muss FilaMan am PC im Browser offen sein.",
    "Through FilaMan. FilaMan has to be open in a browser on the PC.",
    "Via FilaMan, qui doit être ouvert dans un navigateur sur le PC.",
    "通过 FilaMan 打印。需在电脑浏览器中打开 FilaMan。" },  // STR_PCP_SUB
  { "Spulen-Etikett",
    "Spool label",
    "Étiquette bobine",
    "料盘标签" },  // STR_PCP_SPOOL
  { "Filament-Etikett",
    "Filament label",
    "Étiquette filament",
    "耗材标签" },  // STR_PCP_FILAMENT
  { "Wird an FilaMan gesendet ...",
    "Sending to FilaMan ...",
    "Envoi à FilaMan ...",
    "正在发送至 FilaMan ..." },  // STR_PCP_SENDING
  { "An FilaMan gesendet",
    "Sent to FilaMan",
    "Envoyé à FilaMan",
    "已发送至 FilaMan" },  // STR_PCP_SENT_TITLE
  { "Das Etikett erscheint im offenen FilaMan-Tab. Dort drucken.",
    "The label shows up in the open FilaMan tab. Print it from there.",
    "L'étiquette s'affiche dans l'onglet FilaMan ouvert. Imprimez-la.",
    "标签已显示在打开的 FilaMan 页面中，请在页面内打印。" },  // STR_PCP_SENT_TEXT
  { "Nicht gesendet",
    "Not sent",
    "Non envoyé",
    "发送失败" },  // STR_PCP_FAIL_TITLE
  { "Dieses FilaMan nimmt noch keine Druckanfragen an. Nötig ist FilaMan 1.4.3 oder neuer.",
    "This FilaMan does not take print requests yet. It needs FilaMan 1.4.3 or newer.",
    "Ce FilaMan ne gère pas encore l'impression sur PC. Il faut FilaMan 1.4.3 ou plus récent.",
    "当前 FilaMan 暂不支持接收打印请求，需升级至 1.4.3 或更高版本。" },  // STR_PCP_NO_ROUTE
  { "Spule per ID",
    "Spool by ID",
    "Bobine par ID",
    "按 ID 查料盘" },  // STR_BTN_SPOOL_BY_ID
  { "Die ID steht in Spoolman und auf dem Etikett. Ohne Tag wird das Gewicht nur gespeichert, wenn du \"Gewicht updaten\" tippst.",
    "The ID is shown in Spoolman and on the label. Without a tag the weight is saved only when you tap \"Update Weight\".",
    "L'ID figure dans Spoolman et sur l'étiquette. Sans tag, le poids n'est enregistré que si vous touchez \"Envoyer le poids\".",
    "ID 显示在 Spoolman 及标签上。无标签时，仅在点击\"更新重量\"后才会保存重量。" },  // STR_IDPAD_INFO
  { "Suchen",
    "Search",
    "Chercher",
    "搜索" },  // STR_IDPAD_SEARCH
  { "Suche ...",
    "Searching ...",
    "Recherche ...",
    "正在搜索 ..." },  // STR_IDPAD_SEARCHING
  { "Diese Spule",
    "This spool",
    "Cette bobine",
    "选择此料盘" },  // STR_IDPAD_THIS_SPOOL
  { "Keine Spule mit ID %d",
    "No spool with ID %d",
    "Aucune bobine ID %d",
    "未找到 ID 为 %d 的料盘" },  // STR_IDPAD_NOT_FOUND
  { "Ziffern prüfen und erneut suchen.",
    "Check the digits and search again.",
    "Vérifiez les chiffres et recherchez.",
    "请核对数字后重新搜索。" },  // STR_IDPAD_NOT_FOUND_HINT
  { "Per ID geladen - kein Tag",
    "Loaded by ID - no tag",
    "Chargée par ID - sans tag",
    "按 ID 加载 - 无标签" },  // STR_ID_SPOOL_STATUS
  { "An: nach dem Wiegen einer bekannten Spule fragt die Waage beim Abheben, in welches AMS-Fach sie geht, und meldet das der AMS-Quelle. Die trägt die Spule in Spoolman bei diesem Fach ein.\n\nDie AMS-Quelle konfiguriert das Fach dabei über MQTT am Drucker mit - Material, Farbe und Temperaturen. Das ist gewollt, aber es wirkt auf den Drucker, nicht nur auf die Datenbank.",
    "On: after a known spool has been weighed, the scale asks on removal which AMS bay it goes into and reports that to the AMS source, which records the spool in Spoolman for that bay.\n\nThe AMS source also configures the bay on the printer over MQTT while doing so - material, colour and temperatures. That is intended, but it acts on the printer, not only on the database.",
    "Activé : après la pesée d'une bobine connue, la balance demande au retrait dans quel bac AMS elle va, et le transmet à la source AMS, qui l'enregistre dans Spoolman pour ce bac.\n\nLa source AMS configure aussi ce bac sur l'imprimante par MQTT : matériau, couleur, températures. C'est voulu, mais cela agit sur l'imprimante, pas seulement sur la base.",
    "开启后：已知料盘称重完成并取下时，秤会询问要放入哪个 AMS 槽位，并上报给 AMS 数据源以在 Spoolman 中记录该槽位。\n\n同时，AMS 数据源会通过 MQTT 配置打印机上的对应槽位（材质、颜色与温度）。此为正常联动，但会直接修改打印机设置，而非仅更新数据库。" },  // STR_SMAMS_ASK_INFO
  { "AMS-Quelle", "AMS source", "Source AMS", "AMS 数据源" },  // STR_W_C_AMS_SOURCE
  { "Spoolman kennt keine Drucker. Die AMS-Ansicht braucht deshalb einen zweiten Server, der den Drucker mithört und in dieselbe Spoolman-Datenbank bucht, zum Beispiel OpenSpoolman. Leer lassen schaltet die AMS-Ansicht ab.",
    "Spoolman knows no printers. The AMS view therefore needs a second server that listens to the printer and books into the same Spoolman database, OpenSpoolman for example. Leave it empty to switch the AMS view off.",
    "Spoolman ne connaît aucune imprimante. La vue AMS a donc besoin d'un second serveur qui écoute l'imprimante et enregistre dans la même base Spoolman, par exemple OpenSpoolman. Laissez vide pour désactiver la vue AMS.",
    "Spoolman 本身不识别打印机，因此 AMS 视图需要另一个监听打印机并同步至同一 Spoolman 数据库的服务（如 OpenSpoolman）。留空则关闭 AMS 视图。" },  // STR_W_AMS_SOURCE_HINT
  { "Adresse", "Address", "Adresse",
    "地址" },  // STR_W_AMS_SOURCE_ADDR
  { "Lagerort beim Zuweisen", "Location on assignment", "Emplacement AMS",
    "分配时更新位置" },  // STR_SMAMS_LOC
  { "Zum Beispiel \"X1C AMS 1\"", "For example \"X1C AMS 1\"", "Par exemple « X1C AMS 1 »",
    "例如 \"X1C AMS 1\"" },  // STR_SMAMS_LOC_SUB
  { "An: wer eine Spule einem AMS-Fach zuweist, setzt damit auch ihren Lagerort in Spoolman auf die Einheit, etwa \"X1C AMS 1\". So sieht man auch in Spoolman, wo sie steckt.\n\nWird die Spule auf der Fachkarte wieder entnommen, fragt die Waage nach dem neuen Lagerort.",
    "On: assigning a spool to an AMS bay also sets its Spoolman location to the unit, for example \"X1C AMS 1\". That way Spoolman shows where it is too.\n\nWhen the spool is taken out again on the bay card, the scale asks for the new location.",
    "Activé : affecter une bobine à un bac AMS règle aussi son emplacement dans Spoolman sur l'unité, par exemple « X1C AMS 1 ». Spoolman montre ainsi où elle se trouve.\n\nSi la bobine est retirée depuis la fiche du bac, la balance demande le nouvel emplacement.",
    "开启后：将料盘分配至 AMS 槽位时，会同步将其 Spoolman 存放位置设为对应设备（如 \"X1C AMS 1\"），方便在 Spoolman 中查看去向。\n\n在槽位卡片上取出料盘时，秤会提示设置新的存放位置。" },  // STR_SMAMS_LOC_INFO
  { "Server nimmt keine Zuweisung an", "The server accepts no assignment",
    "Le serveur refuse l'affectation",
    "服务器不支持分配操作" },  // STR_AMSV_ERR_READONLY
  { "Drucker, Spule oder Fach unbekannt", "Printer, spool or bay unknown",
    "Imprimante, bobine ou bac inconnu",
    "未知的打印机、料盘或槽位" },  // STR_AMSV_ERR_UNKNOWN
  { "Spoolman antwortet dem Server nicht", "Spoolman is not answering the server",
    "Spoolman ne répond pas au serveur",
    "Spoolman 未响应服务器" },  // STR_AMSV_ERR_INVENTORY
  { "Drucker nicht verbunden", "Printer not connected",
    "Imprimante hors ligne",
    "打印机未连接" },  // STR_AMSV_ERR_OFFLINE
  { "Spule aus dem AMS nehmen?", "Take the spool out of the AMS?",
    "Retirer la bobine de l'AMS ?",
    "从 AMS 中取出此料盘？" },  // STR_AMSD_TAKEOUT_Q
  { "Entnehmen", "Take out",
    "Retirer",
    "取出" },  // STR_AMSD_TAKEOUT_BTN
  { "Erkannt: %s %s", "Found: %s %s",
    "Détecté : %s %s",
    "已发现: %s %s" },  // STR_W_AMS_SOURCE_SEEN
  { "nur lesend, kann nicht zuweisen", "read only, cannot assign",
    "lecture seule, pas d'affectation",
    "只读模式，无法分配" },  // STR_W_AMS_SOURCE_RO
  { "Noch nicht erreicht. Die Waage fragt etwa 20 s nach dem Start und beim Öffnen der AMS-Ansicht.", "Not reached yet. The scale asks about 20 s after starting and when the AMS view opens.",
    "Pas encore joint. La balance interroge environ 20 s après le démarrage et à l'ouverture de la vue AMS.",
    "尚未连接。秤会在开机约 20 秒后以及打开 AMS 视图时自动查询。" },  // STR_W_AMS_SOURCE_UNSEEN
  { "Creality-CFS-Tags lesen und schreiben", "Read and write Creality CFS tags",
    "Lire et écrire les tags Creality CFS",
    "读写 Creality CFS 标签" },  // STR_W_CREALITY
  { "Liest Creality-CFS-Tags (K2 Plus, K2 Pro, K2 Max, Hi): Material, Farbe und Gewicht. Bietet an, einen leeren MIFARE-Tag mit den Daten der Spule zu beschreiben, damit das CFS ihn erkennt. Ein unbekannter 4-Byte-Tag wird zuerst als Creality-Tag versucht, danach als Bambu-Tag.",
    "Reads Creality CFS tags (K2 Plus, K2 Pro, K2 Max, Hi): material, colour and weight. Offers to write a blank MIFARE tag with the spool's data so the CFS recognises it. An unknown 4 byte tag is tried as a Creality tag first, then as a Bambu tag.",
    "Lit les tags Creality CFS (K2 Plus, K2 Pro, K2 Max, Hi) : matériau, couleur et poids. Propose d'écrire les données de la bobine sur un tag MIFARE vierge pour que le CFS le reconnaisse. Un tag de 4 octets inconnu est d'abord essayé comme tag Creality, puis comme tag Bambu.",
    "读取 Creality CFS 标签（K2 Plus、K2 Pro、K2 Max、Hi）的材质、颜色和重量。支持将当前料盘数据写入空白 MIFARE 标签以供 CFS 识别。未知的 4 字节标签会优先按 Creality 标签尝试读取，其次按 Bambu 标签尝试。" },  // STR_W_CREALITY_HINT
  { "Kein leerer Tag. Er wurde nicht verändert.",
    "Not a blank tag. It was left as it is.",
    "Tag non vierge. Il est resté tel quel.",
    "非空白标签，未做修改。" },  // STR_TW_ERR_NOT_BLANK
  { "Als CFS-Tag beschreiben?", "Write as a CFS tag?", "Écrire comme tag CFS ?",
    "写入为 CFS 标签？" },  // STR_TW_CFS_ASK_TITLE
  { "Der leere Tag bekommt die Daten dieser Spule, damit das Creality CFS sie erkennt.",
    "The blank tag gets this spool's data, so the Creality CFS recognises it.",
    "Le tag vierge reçoit les données de la bobine, que le CFS Creality reconnaîtra.",
    "将此料盘数据写入空白标签，以便 Creality CFS 识别。" },  // STR_TW_CFS_ASK_HINT
  { "Der Tag antwortet nicht. Spule kurz anheben und wieder genauso hinstellen.",
    "The tag does not answer. Lift the spool briefly and put it back the same way.",
    "Le tag ne répond pas. Soulevez un instant la bobine et reposez-la pareil.",
    "标签无响应，请短暂提起料盘后再原位放回。" },  // STR_TW_CFS_REPLACE
  { "CFS-Tag aktualisieren?", "Update the CFS tag?", "Actualiser le tag CFS ?",
    "更新 CFS 标签？" },  // STR_TW_CFS_UPD_TITLE
  { "In Spoolman stehen andere Daten als auf dem Tag. Er wird mit den aktuellen Daten neu beschrieben.",
    "Spoolman holds different data than the tag. It is written again with the current data.",
    "Spoolman contient d'autres données que le tag. Il est réécrit avec les données actuelles.",
    "Spoolman 中的数据与标签不一致，将使用最新数据重新写入。" },  // STR_TW_CFS_UPD_HINT
  { "Creality-Tag überschreiben?", "Overwrite the Creality tag?",
    "Écraser le tag Creality ?",
    "覆盖 Creality 标签？" },  // STR_TW_CFS_OVR_TITLE
  { "Der Tag trägt die Daten eines anderen Filaments. Nur überschreiben, wenn die Spule neu bespult wurde.",
    "The tag carries another filament's data. Only overwrite it if the spool has been refilled.",
    "Le tag porte les données d'un autre filament. À n'écraser que si la bobine a été rembobinée.",
    "标签内已有其他耗材数据，仅在重新绕制新料后才建议覆盖。" },  // STR_TW_CFS_OVR_HINT
  { "Spool-ID auf den Tag schreiben?", "Write the spool ID to the tag?",
    "Écrire l'ID de bobine sur le tag ?",
    "将料盘 ID 写入标签？" },  // STR_TW_CFS_SID_TITLE
  { "Der Original-Tag trägt Crealitys Seriennummer statt der Spool-ID. Damit verknüpft CFSync die falsche Spule. Material und Farbe bleiben gleich.",
    "The original tag carries Creality's serial instead of the spool ID, so CFSync links the wrong spool. Material and colour stay the same.",
    "Le tag d'origine porte le numéro de Creality au lieu de l'ID de bobine, CFSync lie donc la mauvaise bobine. Matériau et couleur restent.",
    "原厂标签记录的是 Creality 序列号而非料盘 ID，会导致 CFSync 绑定错误料盘。材质和颜色将保持不变。" },  // STR_TW_CFS_SID_HINT
  // Backend page: a second, parked server set
  // %s is the parked set's name, or its address when it has none.
  { "Zweiter Server",
    "Second server",
    "Second serveur",
    "备用服务器" },  // STR_W_C_SERVER_SETS
  { "Die Waage merkt sich zwei Server-Sätze: Adressen und Zugangsdaten aller drei Backends und die AMS-Quelle. Wechseln tauscht sie aus, zum Beispiel zwischen Heimserver und Test-Pi. Welches Backend aktiv ist, bleibt gleich.",
    "The scale keeps two server sets: the addresses and credentials of all three backends and the AMS source. Switching exchanges them, between a home server and a test Pi, say. Which backend is active stays the same.",
    "La balance garde deux jeux de serveurs : adresses et identifiants des trois backends, et la source AMS. Basculer les échange, par exemple entre un serveur maison et un Pi de test. Le backend actif reste le même.",
    "秤可保存两套服务器配置（包含全部三个后端的地址、凭据及 AMS 来源）。切换即可在两套配置（例如家庭服务器与测试 Pi）间互换，当前启用的后端类型保持不变。" },  // STR_W_SETS_HINT
  { "Aktiv",
    "Active",
    "Actif",
    "当前启用" },  // STR_W_SETS_ACTIVE
  { "Geparkt",
    "Parked",
    "En réserve",
    "已备用" },  // STR_W_SETS_PARKED
  { "Wechseln zu: %s",
    "Switch to: %s",
    "Passer à : %s",
    "切换至：%s" },  // STR_SETS_SWITCH_TO
  { "Den jetzigen Satz parken? Danach sind alle Adressen leer, bis die des zweiten Servers eingetragen sind.",
    "Park the current set? Every address is empty afterwards, until the second server's are entered.",
    "Mettre le jeu actuel en réserve ? Toutes les adresses restent ensuite vides jusqu'à ce que vous saisissiez celles du second serveur.",
    "将当前配置设为备用？之后所有地址将清空，以便录入第二台服务器的信息。" },  // STR_W_SETS_CREATE_ASK
  { "z. B. Zuhause",
    "e.g. Home",
    "p. ex. Maison",
    "例如：家里" },  // STR_W_SETS_NAME_PH
  { "Für zwei Installationen, etwa Heimserver und Test-Pi: Die Waage merkt sich beide und wechselt mit einem Klick.",
    "For two installations, a home server and a test Pi, say: the scale keeps both and switches with one click.",
    "Pour deux installations, par exemple un serveur maison et un Pi de test : la balance garde les deux et bascule en un clic.",
    "适用于双环境部署（例如家庭服务器与测试 Pi）：秤会同时保存两套配置，支持一键切换。" },  // STR_W_SETS_OFF_HINT
  { "Bearbeiten",
    "Edit",
    "Modifier",
    "编辑" },  // STR_W_SETS_EDIT
  { "Zweiten Server löschen",
    "Remove second server",
    "Supprimer le second serveur",
    "移除备用服务器" },  // STR_W_SETS_DELETE
  // %s is the parked set's name, or its address when it has none.
  { "Den geparkten Satz %s löschen? Seine Adressen und Zugangsdaten sind dann weg. Der aktive Satz bleibt.",
    "Delete the parked set %s? Its addresses and credentials are gone then. The active set stays.",
    "Supprimer le jeu en réserve %s ? Ses adresses et identifiants sont alors perdus. Le jeu actif reste.",
    "确定删除备用配置 %s？其地址和凭据将被清除，当前启用的配置不受影响。" },  // STR_W_SETS_DELETE_ASK
  // The colour tile a tap on a swatch opens: what kind of colour it shows,
  // beside its codes. A Bambu tag does not say gradient or dual colour.
  { "Zwei Farben",
    "Two colours",
    "Deux couleurs",
    "双色" },  // STR_COLOR_TILE_TWO
  { "Transluzent",
    "Translucent",
    "Translucide",
    "半透明" },  // STR_COLOR_TILE_CLEAR
  // The screenshot card's copy button, its tooltip and what it turns into for
  // two seconds; the hint stands under a picture when the browser refuses.
  { "Bild kopieren",
    "Copy image",
    "Copier l'image",
    "复制图片" },  // STR_W_SHOT_COPY
  { "Kopiert",
    "Copied",
    "Copiée",
    "已复制" },  // STR_W_SHOT_COPIED
  { "Über http lässt der Browser kein Bild kopieren. Rechtsklick aufs Bild, dann \"Bild kopieren\".",
    "Over http the browser does not let a page copy an image. Right-click the picture, then \"Copy image\".",
    "En http, le navigateur ne laisse pas copier une image. Clic droit sur l'image, puis « Copier l'image ».",
    "在 http 连接下浏览器不允许网页直接复制图片。请右键点击图片，然后选择\"复制图片\"。" },  // STR_W_SHOT_COPY_HINT
  // The GitHub update screen's headline before anything was searched for.
  { "Noch nicht gesucht",
    "Not checked yet",
    "Pas encore vérifié",
    "尚未检查" },  // STR_GH_OTA_NOT_CHECKED
  // The product name beside the version chip on Info & Support.
  { "SpoolmanScale",
    "SpoolmanScale",
    "SpoolmanScale",
    "SpoolmanScale" },  // STR_INFO_PRODUCT
  // Info & Support: the line under each tile's name.
  { "Projekt unterstützen",
    "Support the project",
    "Soutenir le projet",
    "赞助支持项目" },  // STR_INFO_SUB_KOFI
  { "Code und Fehler melden",
    "Code and bug reports",
    "Code et signalements",
    "源码与问题反馈" },  // STR_INFO_SUB_GITHUB
  { "Fragen und Austausch",
    "Questions and chat",
    "Questions et échanges",
    "交流与答疑" },  // STR_INFO_SUB_DISCORD
  { "Gehäuse zum Drucken",
    "Case to print",
    "Boîtier à imprimer",
    "可打印外壳模型" },  // STR_INFO_SUB_MAKER
  // Under a QR code.
  { "Mit der Handykamera scannen",
    "Scan with your phone camera",
    "Scannez avec votre téléphone",
    "使用手机相机扫码" },  // STR_QR_SCAN_HINT
  // The web hand-off: the button that shows the address as a QR code, and its page.
  { "QR-Code",
    "QR code",
    "QR code",
    "二维码" },  // STR_WEB_QR_BTN
  { "Mit der Handykamera scannen, Tippen schließt",
    "Scan with your phone camera, tap to close",
    "Scannez avec votre téléphone, touchez pour fermer",
    "使用手机相机扫码，点击关闭" },  // STR_WEB_QR_HINT
  // Before the IP address under the name.
  { "oder",
    "or",
    "ou",
    "或" },  // STR_WEB_OR
  { "Im Browser API-Key und Gerätecode eintragen:",
    "Enter the API key and device code in a browser:",
    "Saisissez clé d'API et code d'appareil dans le navigateur :",
    "在浏览器中输入 API 密钥和设备码：" },  // STR_WEB_STEP_CREDS
  { "Im Browser den API-Key eintragen:",
    "Enter the API key in a browser:",
    "Saisissez la clé d'API dans le navigateur :",
    "请在浏览器中输入 API 密钥：" },  // STR_WEB_STEP_CREDS_BB
  { "Dort die Grenzwerte für die Trocknungserinnerung einstellen.",
    "Set the limits for the drying reminder there.",
    "Réglez-y les seuils du rappel de séchage.",
    "在此设置烘干提醒的阈值。" },  // STR_WEB_DRY_HINT
  // The file the firmware upload expects, under its status.
  { "SpoolmanScale vX.Y.Z.bin",
    "SpoolmanScale vX.Y.Z.bin",
    "SpoolmanScale vX.Y.Z.bin",
    "SpoolmanScale vX.Y.Z.bin" },  // STR_OTA_FILE_NAME
  // Over the running version, right in the firmware upload's status row.
  { "Installiert", "Installed", "Installée", "已安装" },  // STR_OTA_INSTALLED_CAP
  // Replaces the file name under the status once an upload failed.
  { "Im Browser erneut versuchen", "Try again in the browser",
    "Réessayez dans le navigateur",
    "请在浏览器中重试" },  // STR_OTA_RETRY_HINT
  // The weight button on the main screen, after the automatic weighing has
  // looked at a spool that lay still. 202 px at f16, behind an icon.
  { "%.0f g gesendet",     "%.0f g sent",       "%.0f g envoyés",   "已发送 %.0f g" },  // STR_WB_SENT
  { "%.0f g, unverändert", "%.0f g, unchanged", "%.0f g, inchangé", "%.0f g，未变化" },  // STR_WB_UNCHANGED
  // Heavier than the backend by this much: nothing sent, a tap asks.
  { "%+.0f g, prüfen", "%+.0f g, check", "%+.0f g, à vérifier", "%+.0f g，请检查" },  // STR_WB_RISE
  // The weight popup (weight_popup.cpp). Its first line when the spool
  // reads heavier than stored; %s is the backend's name. 436 px at f14.
  { "Schwerer als in %s: Beutel drauf? Andere Spule?",
    "Heavier than in %s: bag on it? Another spool?",
    "Plus lourde que dans %s : sachet ? Autre bobine ?",
    "比 %s 中更重：带包装袋？放错料盘？" },  // STR_WP_RISE_LINE
  // The large button, f24, 436 px with a tick before it.
  { "%.0f g senden",          "Send %.0f g",        "Envoyer %.0f g",            "发送 %.0f g" },  // STR_WP_SEND
  { "%.0f g trotzdem senden", "Send %.0f g anyway", "Envoyer %.0f g quand même",
    "仍发送 %.0f g" },  // STR_WP_SEND_ANYWAY
  // Under it while the bag switch is on: the reading, and what came off it.
  { "%.0f g abzüglich %.0f g Beutel", "%.0f g less %.0f g for the bag",
    "%.0f g moins %.0f g de sachet",
    "%.0f g 减去 %.0f g 包装袋重" },  // STR_WP_BAG_MINUS
  { "Reaktivieren", "Reactivate", "Réactiver", "重新启用" },  // STR_WP_REACTIVATE
  { "Rest wird %.0f g", "Remaining becomes %.0f g",
    "Le reste passe à %.0f g",
    "剩余量将变为 %.0f g" },  // STR_WP_REACT_SUB
  // The two switch rows under it: title f16, subtitle f12.
  { "Im Beutel gewogen", "Weighed in the bag", "Pesée dans le sachet",
    "带包装袋称重" },  // STR_WP_BAG_ROW
  { "zieht %.0f g ab", "takes off %.0f g", "retire %.0f g",
    "扣除 %.0f g" },  // STR_WP_BAG_SUB
  { "mit Beutel wären es %.0f g", "with the bag it would be %.0f g", "avec le sachet : %.0f g",
    "含包装袋重为 %.0f g" },  // STR_WP_BAG_HINT
  { "Automatisch senden", "Send automatically", "Envoi automatique",
    "自动发送" },  // STR_WP_AUTO_ROW
  { "nach 4 s Ruhe, ohne Beutel", "after 4 s at rest, without bag",
    "après 4 s immobile, sans sachet",
    "静止 4 秒后，不含包装袋" },  // STR_WP_AUTO_SUB
  // The bottom row: 120 px for Archive, 150 px each for the other two, f14.
  { "Archivieren", "Archive", "Archiver", "归档" },  // STR_WP_ARCHIVE
  { "Optionen",    "Options", "Options",  "选项" },  // STR_WP_OPTIONS
  // The popup's Options, f16 titles and f12 subtitles.
  { "Als volle Spule übernehmen", "Take as a full spool",
    "Reprendre comme bobine pleine",
    "设为满盘" },  // STR_WP_FULL
  { "Startgewicht wird %.0f g, Rest voll", "Initial weight becomes %.0f g, full",
    "Poids initial %.0f g, bobine pleine",
    "初始重量设为 %.0f g，满盘" },  // STR_WP_FULL_SUB
  { "Leere Spule wiegen", "Weigh the empty spool",
    "Peser la bobine vide",
    "称量空盘" },  // STR_WP_WEIGH_EMPTY
  { "jetzt auf der Waage: %.0f g", "on the scale now: %.0f g",
    "sur la balance : %.0f g",
    "当前秤上重量：%.0f g" },  // STR_WP_WEIGH_EMPTY_SUB
  { "Leergewicht eingeben", "Enter the empty weight",
    "Saisir le poids à vide",
    "输入空盘重" },  // STR_WP_TYPE_EMPTY
  { "bekannt oder vom Hersteller", "known, or from the maker",
    "connu ou donné par le fabricant",
    "已知空重或厂商标称值" },  // STR_WP_TYPE_EMPTY_SUB
  // Where an empty spool weight goes. Title f16 on 436 px.
  { "%.0f g als Leergewicht speichern für", "Store %.0f g as the empty weight of",
    "Enregistrer %.0f g comme poids à vide pour",
    "将 %.0f g 保存为空盘重，应用于" },  // STR_SW_SCOPE_TITLE
  { "Nur diese Spule", "This spool only",
    "Cette bobine seulement",
    "仅此料盘" },  // STR_SW_ONLY_SPOOL
  { "Alle Spulen dieses Filaments", "Every spool of this filament",
    "Toutes les bobines de ce filament",
    "此耗材的所有料盘" },  // STR_SW_ALL_FILAMENT
  { "Alle Spulen des Herstellers", "Every spool of this brand",
    "Toutes les bobines de la marque",
    "此品牌的所有料盘" },  // STR_SW_ALL_VENDOR
  // On the row whose value applies now, f14 right of the title.
  { "gilt: %.0f g", "now: %.0f g", "actuel : %.0f g", "当前：%.0f g" },  // STR_SW_CURRENT
  // The first setup frame: n of N right in the header, f14.
  { "%d von %d", "%d of %d", "%d sur %d", "第%d/%d步" },  // STR_SETUP_STEP_OF
  // Under the logo on the language screen, before any language is chosen,
  // so it reads the same in every column. f16 on 456 px.
  { "Welcome / Willkommen / Bienvenue", "Welcome / Willkommen / Bienvenue",
    "Welcome / Willkommen / Bienvenue",
    "Welcome / Willkommen / Bienvenue / 欢迎" },  // STR_WELCOME_TRILINGUAL
  // Above the four step tiles of the welcome screen, f14.
  { "Diese Schritte folgen:", "The steps ahead:", "Les étapes à venir :", "后续设置步骤：" },  // STR_WELCOME_STEPS_AHEAD
  // The step tiles, f14 under a number disc, 100 px.
  { "WLAN",       "WiFi",    "Wi-Fi",   "WiFi" },  // STR_SETUP_TILE_WIFI
  { "Verwaltung", "Backend", "Gestion", "后台服务" },  // STR_SETUP_TILE_BACKEND
  { "Server",     "Server",  "Serveur", "服务器" },  // STR_SETUP_TILE_SERVER
  { "Waage",      "Scale",   "Balance", "秤" },  // STR_SETUP_TILE_SCALE
  // The welcome screen's two answers, f16: quiet 150 px, main 306 px.
  { "Überspringen", "Skip",     "Passer",      "跳过" },  // STR_SETUP_SKIP
  { "Los geht's",   "Let's go", "C'est parti", "开始设置" },  // STR_SETUP_START
  // WiFi step. The rescan button, quiet, f16 in 150 px.
  { LV_SYMBOL_REFRESH "  Neu suchen", LV_SYMBOL_REFRESH "  Rescan",
    LV_SYMBOL_REFRESH "  Actualiser",
    LV_SYMBOL_REFRESH "  重新扫描" },  // STR_WIFI_RESCAN
  // The connect card: its title f16 and the line under it f12, 420 px each.
  { "Verbunden mit %s", "Connected to %s",
    "Connecté à %s",
    "已连接至 %s" },  // STR_WIFI_CONNECTED_TO
  { "IP %s  |  Signal: %s", "IP %s  |  Signal: %s",
    "IP %s  |  Signal : %s",
    "IP %s  |  信号: %s" },  // STR_WIFI_CONN_DETAIL
  { "Keine Verbindung zu %s", "Could not connect to %s",
    "Pas de connexion à %s",
    "无法连接至 %s" },  // STR_WIFI_NO_LINK
  { "Passwort falsch oder Router zu weit weg.", "Wrong password, or the router is too far away.",
    "Mot de passe erroné ou routeur trop loin.",
    "密码错误或路由器距离过远。" },  // STR_WIFI_FAIL_HINT
  // After a failed connect, the main button, f16.
  { "Passwort ändern", "Change password", "Modifier le mot de passe", "修改密码" },  // STR_WIFI_PASS_AGAIN
  // Backend step. The docs button across the bar f16.
  { "Noch keinen Server? Zur Anleitung", "No server yet? See the guide",
    "Pas encore de serveur ? Le guide",
    "还没有服务器？查看指南" },  // STR_SETUP_NO_SERVER
  // The outline beside a backend's name, f12: what it asks of the user.
  { "Eigener Server nötig",      "Needs your own server", "Serveur personnel requis", "需自建服务器" },  // STR_HOSTING_SELF
  { "Kein eigener Server nötig", "No server of your own", "Sans serveur personnel",
    "无需自建服务器" },  // STR_HOSTING_ONLINE
  // One line under a backend's name, f12 in 350 px.
  { "Weit verbreitet, für Klipper und OctoPrint", "Widely used, works with Klipper and OctoPrint",
    "Très répandu, pour Klipper et OctoPrint",
    "广泛使用，支持 Klipper 与 OctoPrint" },  // STR_BACKEND_DESC_SPOOLMAN
  { "Filamentverwaltung mit Plugins", "Filament manager with plugins",
    "Gestion de filament avec plugins",
    "支持插件的耗材管理工具" },  // STR_BACKEND_DESC_FILAMAN
  { "Bambu-Lab-Druckerverwaltung mit Inventar", "Bambu Lab printer manager with inventory",
    "Gestion Bambu Lab avec inventaire",
    "带库存管理的 Bambu Lab 打印机工具" },  // STR_BACKEND_DESC_BAMBUDDY
  // Address step: the example under the field, f12 in 200 px, %s the port.
  { "z. B. 192.168.1.20:%s", "e.g. 192.168.1.20:%s", "ex. 192.168.1.20:%s", "例如 192.168.1.20:%s" },  // STR_SP_EXAMPLE
  // The bar: main f16, quiet f16 in 150 px.
  { "Verbinden",  "Connect",    "Connecter",  "连接" },  // STR_SP_CONNECT
  { "Im Browser", "In browser", "Navigateur", "在浏览器中" },  // STR_SP_IN_BROWSER
  // The result card: title f16 in 180 px, the line under it f12, wraps.
  { "Verbunden", "Connected",
    "Connecté",
    "已连接" },  // STR_SP_CONNECTED
  { "Server gefunden", "Server found",
    "Serveur trouvé",
    "已找到服务器" },  // STR_SP_REACHED
  { "Keine Antwort", "No answer",
    "Pas de réponse",
    "无响应" },  // STR_SP_NO_ANSWER
  { "Läuft der Server? Stimmt der Port?", "Is the server running? Is the port right?",
    "Serveur lancé ? Port correct ?",
    "服务器是否运行中？端口是否正确？" },  // STR_SP_NO_ANSWER_HINT
  // WiFi list, above the networks, f12: the ESP32-S3 has no 5 GHz radio.
  { "Nur 2,4-GHz-WLAN", "2.4 GHz WiFi only", "Wi-Fi 2,4 GHz uniquement", "仅支持 2.4 GHz WiFi" },  // STR_WIFI_24_ONLY
  // The quiet answer of a step that can wait, f16 in 150 px.
  { "Später", "Later", "Plus tard", "稍后" },  // STR_SETUP_LATER
  // The credentials step's title, f18 in 300 px.
  { "Zugangsdaten", "Credentials", "Identifiants", "凭据" },  // STR_SETUP_CREDS_TITLE
  // Guided calibration. The three step chips, f14.
  { "Leeren",   "Empty", "Vider",    "清空" },  // STR_CAL_STEP_EMPTY
  { "Auflegen", "Place", "Poser",    "放置" },  // STR_CAL_STEP_PLACE
  { "Prüfen",   "Check", "Vérifier", "核对" },  // STR_CAL_STEP_CHECK
  // Step 1: the instruction f16 in 270 px, the caption over the live weight f12.
  { "Bitte Auflagefläche leeren.", "Please clear the scale.", "Videz le plateau.", "请清空秤盘。" },  // STR_CAL_EMPTY_PAN
  { "Waage jetzt",                 "Scale now",               "Balance",           "当前读数" },  // STR_CAL_SCALE_NOW
  // Step 1, the line over the bar, f12 in 456 px: in the setup where to find
  // the calibration later (settings, scale menu, row), in the settings the
  // factor that stands.
  { "Kein Gewicht zur Hand? Später unter %s > %s > %s.",
    "No weight at hand? Later under %s > %s > %s.",
    "Pas de poids ? Plus tard : %s > %s > %s.",
    "手边没有砝码？稍后可在 %s > %s > %s 中校准。" },  // STR_CAL_LATER_WHERE
  { "Aktueller Faktor: %.2f", "Current factor: %.2f", "Facteur actuel : %.2f", "当前系数: %.2f" },  // STR_CAL_CUR_FACTOR
  { "Nullen",                 "Zero",                 "Mettre à zéro",         "归零" },  // STR_CAL_ZERO_BTN
  // Step 2: f16 in 200 px, wraps to two lines; the hint under it f14.
  { "Bekanntes Gewicht auflegen.", "Place a known weight.", "Posez un poids connu.",
    "请放上已知重量的物体。" },  // STR_CAL_PLACE_KNOWN
  { "Optimal ca. 1 kg.", "Ideally about 1 kg.", "Idéalement 1 kg.",
    "理想重量约 1 kg。" },  // STR_CAL_ABOUT_1KG
  // Step 3: the caption over the live weight f12, the entered weight f14,
  // the new factor f12.
  { "Die Waage zeigt jetzt", "The scale now reads", "La balance affiche",     "当前秤显示" },  // STR_CAL_SHOWS_NOW
  { "Eingegeben: %s g",      "Entered: %s g",       "Saisi : %s g",           "已输入: %s g" },  // STR_CAL_ENTERED
  { "Neuer Faktor: %.2f",    "New factor: %.2f",    "Nouveau facteur : %.2f", "新系数: %.2f" },  // STR_CAL_NEW_FACTOR
  // Step 3's answers, f16: quiet 150 px, main 290 px.
  { "Nochmal", "Again",       "Refaire",     "重试" },  // STR_CAL_AGAIN
  { "Passt",   "Looks right", "C'est juste", "准确" },  // STR_CAL_LOOKS_RIGHT
  // Scale menu rows, the line under the title f12.
  { "552 g statt 551,8 g", "552 g instead of 551.8 g",
    "552 g au lieu de 551,8 g",
    "显示 552 g 而非 551.8 g" },  // STR_WHOLE_GRAM_SUB
  { "Kalibrierung zurücksetzen", "Reset calibration",
    "Réinitialiser l'étalonnage",
    "重置校准" },  // STR_CAL_RESET_ROW
  { "Faktor und Tara auf Anfang, mit Rückfrage", "Factor and tare back to the start, asks first",
    "Facteur et tare remis à zéro, après confirmation",
    "系数和去皮恢复初始，先确认" },  // STR_CAL_RESET_ROW_SUB
  // The setup's closing screen. Title f18 in 300 px.
  { "Fertig eingerichtet", "All set", "Configuration terminée", "设置完成" },  // STR_SETUP_DONE_TITLE
  // Where something left open is found: settings > menu > row, f12.
  { "%s > %s > %s", "%s > %s > %s", "%s > %s > %s", "%s > %s > %s" },  // STR_SETUP_DONE_PATH
  // Under a summary row, f12 in 220 px; a row title f16 in 220 px.
  { "Zugangsdaten fehlen noch", "Credentials still missing", "Identifiants manquants",
    "尚缺凭据" },  // STR_SETUP_DONE_CREDS
  { "Waage nicht kalibriert", "Scale not calibrated", "Balance non étalonnée",
    "秤未校准" },  // STR_SETUP_DONE_UNCAL
  // Over the bar, f14 in 456 px.
  { "Spule auflegen und NFC-Tag zum Leser ausrichten.", "Place a spool and turn its NFC tag to the reader.",
    "Posez une bobine, tag NFC face au lecteur.",
    "放上料盘并将 NFC 标签对准读卡器。" },  // STR_SETUP_DONE_HINT
  { "Los", "Start",
    "C'est parti",
    "开始" },  // STR_SETUP_GO
  { "Waage jetzt: %s", "Scale now: %s",
    "Balance : %s",
    "当前重量：%s" },  // STR_CAL_LIVE_G
  { "Messwert: %.0f", "Reading: %.0f",
    "Mesure : %.0f",
    "读数：%.0f" },  // STR_CAL_LIVE_RAW
  { "Ab so vielen Tagen seit der letzten Trocknung wird die Spule gelb.", "After this many days since the last drying the spool turns yellow.",
    "Jaune après ce nombre de jours sans séchage.",
    "距上次烘干超过此天数，料盘将变为黄色。" },  // STR_DRY_PAD_HINT_YELLOW
  { "Ab so vielen Tagen seit der letzten Trocknung wird die Spule rot.", "After this many days since the last drying the spool turns red.",
    "Rouge après ce nombre de jours sans séchage.",
    "距上次烘干超过此天数，料盘将变为红色。" },  // STR_DRY_PAD_HINT_RED
  { "So lange bleibt eine abgenommene Spule vorgemerkt, 5 bis 600 s.", "How long a lifted spool stays noted, 5 to 600 s.",
    "Durée pendant laquelle une bobine retirée reste notée, 5 à 600 s.",
    "取下料盘后的记忆保留时间，5 至 600 秒。" },  // STR_AMS_PAD_HINT
  { "Spule per ID verlinken", "Link spool by ID",
    "Lier une bobine par ID",
    "按 ID 绑定料盘" },  // STR_ID_PAD_LINK_TITLE
  { "Spule per ID kopieren", "Copy spool by ID",
    "Copier une bobine par ID",
    "按 ID 复制料盘" },  // STR_ID_PAD_COPY_TITLE
  { "Die ID steht in Spoolman und auf dem Etikett.", "The ID is shown in Spoolman and on the label.",
    "L'ID figure dans Spoolman et sur l'étiquette.",
    "ID 显示在 Spoolman 中及标签上。" },  // STR_ID_PAD_WHERE
  { "Dichte unbekannt, bitte eingeben", "Density unknown, please enter it",
    "Densité inconnue, à saisir",
    "密度未知，请输入" },  // STR_TAGNEW_NEEDS_DENSITY
  { "Eingeben", "Enter",
    "Saisir",
    "输入" },  // STR_TAGNEW_DENSITY_BTN
  { "Dichte des Filaments", "Filament density",
    "Densité du filament",
    "耗材密度" },  // STR_DENSITY_PAD_TITLE
  { "In g/cm3, 0.50 bis 4.00. PLA etwa 1.24, PETG 1.27.", "In g/cm3, 0.50 to 4.00. PLA about 1.24, PETG 1.27.",
    "En g/cm3, 0.50 à 4.00. PLA env. 1.24, PETG 1.27.",
    "g/cm3，0.50-4.00。PLA 约 1.24，PETG 1.27。" },  // STR_DENSITY_PAD_HINT
  { "Hinterlegte Dichte für %s: %.2f", "Typical density for %s: %.2f",
    "Densité typique pour %s : %.2f",
    "%s 典型密度：%.2f" },  // STR_TAGNEW_DENSITY_TYPICAL
  { "Typisch für %s: %.2f g/cm3. OK übernimmt den Wert, oder einen eigenen eintippen.", "Typical for %s: %.2f g/cm3. OK takes it, or type your own.",
    "Typique pour %s : %.2f g/cm3. OK la reprend, ou saisissez la vôtre.",
    "%s 典型值：%.2f g/cm3。点确认采用，或手动输入。" },  // STR_DENSITY_PAD_TYPICAL
  { "Übernehmen", "Use",
    "Utiliser",
    "采用" },  // STR_DENSITY_TAKE
  { "Ändern", "Change",
    "Modifier",
    "修改" },  // STR_DENSITY_CHANGE
  { "Für das schmale Band gibt es ein festes Etikett: Hersteller, Material, Name, auf dem Spulenetikett dazu die Nummer. Deine Vorlage bleibt gespeichert und gilt wieder, sobald ein anderer Drucker gewählt ist.",
    "The narrow tape has a fixed label: maker, material, name, and on a spool label its number. Your template stays saved and applies again once another printer is picked.",
    "Le ruban étroit a une étiquette fixe : fabricant, matière, nom et, sur l'étiquette de bobine, son numéro. Votre modèle reste enregistré et s'applique de nouveau dès qu'une autre imprimante est choisie.",
    "窄标签带使用固定版式：厂商、材质、名称，料盘标签还会显示编号。您的自定义模板已保存，切换回其他打印机后将重新生效。" },  // STR_W_L_TAPE_FIXED
  { "Der Server nimmt den Zugang nicht an. Bitte die Zugangsdaten prüfen.", "The server does not accept the access. Please check the credentials.",
    "Le serveur n'accepte pas cet accès. Vérifiez les identifiants.",
    "服务器拒绝访问，请检查凭据。" },  // STR_REFUSED_ACCESS_TEXT
  { "Konto nicht aktiv", "Account not active",
    "Compte inactif",
    "账户未激活" },  // STR_REFUSED_ACCOUNT
  { "Der Server lässt dieses Konto gerade nicht zu, zum Beispiel weil es abgelaufen ist.", "The server does not allow this account right now, for example because it has expired.",
    "Le serveur n'autorise pas ce compte pour le moment, par exemple s'il a expiré.",
    "服务器当前不允许使用此账户，可能是因为账户已过期。" },  // STR_REFUSED_ACCOUNT_TEXT
  { "Zu viele Anfragen", "Too many requests",
    "Trop de requêtes",
    "请求过于频繁" },  // STR_REFUSED_BUSY
  { "Der Server bremst die Waage gerade aus. Bitte später noch einmal versuchen.", "The server is holding the scale back right now. Please try again later.",
    "Le serveur limite la balance pour le moment. Réessayez plus tard.",
    "服务器暂时限制了秤的请求，请稍后再试。" },  // STR_REFUSED_BUSY_TEXT
  { "Leergewicht fehlt",
    "Empty weight missing",
    "Poids à vide absent",
    "缺少空盘重量" },  // STR_TARE_MISSING
  { "Der Server speichert das Gewicht erst, wenn das Leergewicht dieser Spule bekannt ist.",
    "The server stores the weight once this spool's empty weight is known.",
    "Le serveur n'enregistre le poids qu'une fois le poids à vide de cette bobine connu.",
    "需先录入此料盘的空盘重量，服务器才会保存称重数据。" },  // STR_TARE_MISSING_TEXT
  { "Eintragen",
    "Enter it",
    "Saisir",
    "去录入" },  // STR_TARE_MISSING_ENTER
  { "Gewicht nicht gespeichert",
    "Weight not saved",
    "Poids non enregistré",
    "重量未保存" },  // STR_WEIGHT_NOT_SAVED
  { "Der Server hat das Gewicht nicht angenommen. Bitte noch einmal senden.",
    "The server did not accept the weight. Please send it again.",
    "Le serveur n'a pas accepté le poids. Veuillez l'envoyer à nouveau.",
    "服务器未接受该重量数据，请重新发送。" },  // STR_WEIGHT_NOT_SAVED_TEXT
  // The online services: the Internet button, its page, the web cards.
  { "Internet", "Internet",
    "Internet",
    "互联网" },  // STR_BACKEND_INTERNET
  { "Online-Dienste wie Spooly", "Online services such as Spooly",
    "Services en ligne comme Spooly",
    "Spooly 等在线服务" },  // STR_BACKEND_DESC_INTERNET
  { "Online-Dienst wählen", "Choose online service",
    "Choisir le service en ligne",
    "选择在线服务" },  // STR_ONLINE_TITLE
  { "Anderer Dienst", "Other service",
    "Autre service",
    "其他服务" },  // STR_ONLINE_OTHER
  { "Konto mit Spooly Pro nötig", "Needs an account with Spooly Pro",
    "Compte Spooly Pro requis",
    "需要 Spooly Pro 账户" },  // STR_ONLINE_SPOOLY_SUB
  { "Adresse und Schlüssel im Browser", "Address and key in the browser",
    "Adresse et clé dans le navigateur",
    "在浏览器中填写地址和密钥" },  // STR_ONLINE_OTHER_SUB
  { "Die Auswahl stellt um. Adresse und Schlüssel deines lokalen Backends bleiben gespeichert.", "Choosing one switches over. The address and key of your local backend stay stored.",
    "Le choix bascule la balance. L'adresse et la clé de votre backend local restent enregistrées.",
    "选择后将切换服务。本地后端的地址和密钥仍会保留。" },  // STR_ONLINE_NOTE
  { "Online-Dienst", "Online service",
    "Service en ligne",
    "在线服务" },  // STR_ONLINE_SERVICE
  { "Konto", "Account",
    "Compte",
    "账号" },  // STR_ONLINE_ACCOUNT
  { "Spooly Pro nötig", "Needs Spooly Pro",
    "Spooly Pro requis",
    "需要 Spooly Pro" },  // STR_ONLINE_PRO
  { "Aktiv bleibt %s, bis du unten einen Dienst verbindest.", "%s stays active until you connect a service below.",
    "%s reste actif tant que vous ne connectez pas un service ci-dessous.",
    "在下方连接新服务前，%s 将保持启用。" },  // STR_W_ONLINE_KEEPS
  { "Aktiv ist %s. Spoolman, FilaMan oder BamBuddy wechseln zurück, dort ist nichts verloren.", "%s is active. Spoolman, FilaMan or BamBuddy switch back, nothing is lost there.",
    "%s est actif. Spoolman, FilaMan ou BamBuddy ramènent en arrière, rien n'y est perdu.",
    "当前启用：%s。切换回 Spoolman、FilaMan 或 BamBuddy 不会丢失任何数据。" },  // STR_W_ONLINE_ACTIVE
  { "Die Schnittstelle läuft bei Spooly nur mit einem Pro-Konto.", "Spooly offers this interface with a Pro account only.",
    "Spooly ne propose cette interface qu'avec un compte Pro.",
    "Spooly 仅向 Pro 账号提供此接口。" },  // STR_W_ONLINE_PRO
  { "Den Schlüssel erstellst du in deinem Spooly-Konto.", "You create the key in your Spooly account.",
    "La clé se crée dans votre compte Spooly.",
    "请在你的 Spooly 账号中创建密钥。" },  // STR_W_ONLINE_KEY_HINT
  { "Konto anlegen", "Create an account",
    "Créer un compte",
    "创建账号" },  // STR_W_ONLINE_ACCOUNT
  { "Prüfen und verbinden", "Check and connect",
    "Vérifier et connecter",
    "检查并连接" },  // STR_W_ONLINE_CONNECT
  { "Jeder Dienst, der die Spoolman-Schnittstelle spricht. Der Name kommt vom Dienst selbst.", "Any service that speaks Spoolman's interface. The name comes from the service itself.",
    "Tout service qui parle l'interface de Spoolman. Le nom vient du service lui-même.",
    "任何兼容 Spoolman 接口的服务均可使用，名称由该服务本身提供。" },  // STR_W_ONLINE_OTHER_HINT
  { "Komplette Adresse", "Full address",
    "Adresse complète",
    "完整地址" },  // STR_W_ONLINE_ADDR
  { "Ohne https:// geht der Schlüssel unverschlüsselt durchs Internet.", "Without https:// the key crosses the internet unencrypted.",
    "Sans https://, la clé circule en clair sur Internet.",
    "未使用 https:// 时，密钥将在网络中明文传输。" },  // STR_W_ONLINE_HTTP
  { "Ohne https:// geht der Schlüssel unverschlüsselt durchs Internet. Trotzdem verbinden?", "Without https:// the key crosses the internet unencrypted. Connect anyway?",
    "Sans https://, la clé circule en clair sur Internet. Connecter quand même ?",
    "未使用 https:// 时，密钥将在网络中明文传输。仍要连接吗？" },  // STR_W_ONLINE_HTTP_ASK
  { "Für eine neue Adresse trägst du den Schlüssel neu ein.", "A new address needs the key entered again.",
    "Une nouvelle adresse demande de saisir à nouveau la clé.",
    "更改地址后需要重新输入密钥。" },  // STR_W_ONLINE_REKEY
  { "Nummer groß", "Large number",
    "Grand numéro",
    "大号编号" },  // STR_W_L_P_BIG_ID
  { "Nummer rechts", "Number right",
    "Numéro à droite",
    "右侧编号" },  // STR_W_L_P_BIG_ID_SIDE
  { "Anteil der Nummer", "Share of the number",
    "Part du numéro",
    "编号占比" },  // STR_W_L_ID_SHARE
  { "Spooly dunkel", "Spooly dark",
    "Spooly sombre",
    "Spooly 深色" },  // STR_W_THEME_SPOOLY_DARK
  { "Spooly hell", "Spooly light",
    "Spooly clair",
    "Spooly 浅色" },  // STR_W_THEME_SPOOLY_LIGHT
  { "Neue Spule", "New spool",
    "Nouvelle bobine",
    "新建料盘" },  // STR_IDPAD_NEW
  { "Ohne Tag: Vorlage wählen oder neu anlegen",
    "No tag: pick a template or create a new one",
    "Sans tag : choisissez un modèle ou créez-en une",
    "无标签：选择模板或新建料盘" },  // STR_COPY_CTX_TAGLESS
  { "Ohne Tag",       "No tag",        "Sans tag",     "无标签" },  // STR_CTX_NO_TAG
  { "Spule angelegt", "Spool created", "Bobine créée", "料盘已创建" },  // STR_NEWSPOOL_DONE
  { "Ohne Tag findest du sie nur über diese Nummer. Schreib sie auf die Spule.",
    "Without a tag, this number is the only way back to it. Write it on the spool.",
    "Sans tag, il faut ce numéro pour la retrouver. Notez-le sur la bobine.",
    "无标签时，此编号是找回该料盘的唯一凭证，请写在料盘上。" },  // STR_NEWSPOOL_HINT_WRITE
  { "Ohne Tag findest du sie nur über diese Nummer. Das Etikett trägt sie groß.",
    "Without a tag, this number is the only way back to it. The label shows it large.",
    "Sans tag, il faut ce numéro pour la retrouver. L'étiquette l'affiche en grand.",
    "无标签时，此编号是找回该料盘的唯一凭证，标签上已大号显示。" },  // STR_NEWSPOOL_HINT_LABEL
  { "Ohne Tag findest du sie nur über diese Nummer, mit \"Spule per ID\".",
    "Without a tag, this number is the only way back to it, with \"Spool by ID\".",
    "Sans tag, il faut ce numéro pour la retrouver, via \"Bobine par ID\".",
    "无标签时，只能通过\"按编号查盘\"凭此编号找回该料盘。" },  // STR_NEWSPOOL_HINT_NOT_SHOWN
  // Weight button (weight_button.cpp): a tag is read but the pad weighs too
  // little for its spool, so nothing is written.
  { "Spule fehlt", "No spool", "Pas de bobine", "无料盘" },  // STR_WB_NO_SPOOL
  // Busy card while a MIFARE (CFS) tag is written (tag_busy_popup.cpp): a tag
  // that leaves the field before the last block keeps a half written record.
  { "Spule nicht berühren", "Do not touch the spool", "Ne touchez pas la bobine", "请勿触碰料盘" },  // STR_TW_HANDS_OFF
  { "Der Tag wird geschrieben und danach geprüft. Fertig ist er erst, wenn die Bestätigung kommt.",
    "The tag is being written and then checked. It is only done once the confirmation appears.",
    "Le tag est écrit puis vérifié. Il n'est prêt qu'à la confirmation.",
    "正在写入并校验标签，出现确认提示后才算完成。" },  // STR_TW_HANDS_OFF_HINT
  // Tag write popup (tag_write_popup.cpp): a tag put down whose write was cut
  // short and never read back (services/tag_pending.h). %s is the format.
  { "Tag fertig schreiben?", "Finish writing the tag?", "Terminer le tag ?", "继续完成标签写入？" },  // STR_TW_UNF_TITLE
  { "Das Schreiben als %s wurde unterbrochen. Bis es fertig ist, kann der Tag falsch gelesen werden.",
    "Writing it as %s was cut short. Until it is finished, the tag may read wrong.",
    "L'écriture en %s a été interrompue. Tant qu'elle n'est pas terminée, le tag peut être mal lu.",
    "写入 %s 时曾被中断。在完成前，标签可能无法正常读取。" },  // STR_TW_UNF_HINT
  { "So lassen", "Leave it",
    "Laisser",
    "暂不处理" },  // STR_TW_BTN_LEAVE
  { "Anderer Tag auf dem Leser - nicht geschrieben", "A different tag is on the reader - not written",
    "Autre tag sur le lecteur - rien écrit",
    "读卡器上检测到其他标签 - 未写入" },  // STR_TW_ERR_OTHER_TAG_W
  // Tag write popup (tag_write_popup.cpp): a MIFARE card that opens with the
  // factory key but already holds data. %s in the hint is one of the three
  // descriptions below; %s in those is the material and colour, or the text.
  { "Tag enthält Daten", "The tag holds data", "Le tag contient des données", "标签内已有数据" },  // STR_TW_CFS_DATA_TITLE
  { "Darauf steht %s. Überschreiben macht ihn zum CFS-Tag dieser Spule, das Alte ist dann weg.",
    "It holds %s. Overwriting makes it this spool's CFS tag, and the old data is gone.",
    "Il contient %s. L'écraser en fait le tag CFS de cette bobine, et l'ancien contenu est perdu.",
    "标签内含%s。覆盖后将变为此料盘的 CFS 标签，原有数据将被清除。" },  // STR_TW_CFS_DATA_HINT
  { "ein unfertiger CFS-Datensatz (%s)", "an unfinished CFS record (%s)",
    "des données CFS inachevées (%s)",
    "未完成的 CFS 记录（%s）" },  // STR_TW_CFS_DATA_CFS
  { "der Text '%s'", "the text '%s'",
    "le texte '%s'",
    "文本“%s”" },  // STR_TW_CFS_DATA_TEXT
  { "Daten, die die Waage nicht kennt", "data the scale does not recognise",
    "des données inconnues de la balance",
    "秤无法识别的数据" },  // STR_TW_CFS_DATA_UNKNOWN
  { "Überschreiben", "Overwrite", "Écraser", "覆盖" },  // STR_TW_BTN_OVERWRITE
  // The browser's model picker: the recommended two as cards, the rest folded
  { "Weitere Modelle (%d)", "More models (%d)",
    "Autres modèles (%d)",
    "更多型号 (%d)" },  // STR_W_P_MORE_MODELS_FMT
  { "Modell ändern", "Change model",
    "Changer de modèle",
    "更换型号" },  // STR_W_P_CHANGE_MODEL
  { "Fertig", "Done",
    "Terminé",
    "完成" },  // STR_W_P_MODEL_DONE
  { "Ohne Farbband, die günstigsten Etiketten.", "No ribbon, the cheapest labels.",
    "Sans ruban, les étiquettes les moins chères.",
    "无需碳带，标签成本最低。" },  // STR_W_P_WHY_M220
  { "Mit Farbband: Das Etikett übersteht das Trocknen.", "Ribbon: the label survives drying.",
    "Avec ruban : l'étiquette résiste au séchage.",
    "配碳带：标签可耐受烘干高温。" },  // STR_W_P_WHY_M2
  { "Details und Bezugsquellen", "Details and where to buy",
    "Détails et où l'acheter",
    "详情与购买渠道" },  // STR_W_P_BUY_LINK
  // After a model in a name that nobody has printed on yet
  { "exp.", "exp.", "exp.", "实验" },  // STR_PRN_TAG_UNTRIED_SHORT
  // Logs page: the session log card (page_logs_session.cpp), its toolbar
  // and full screen view.
  { "Vollbild",         "Full screen",       "Plein écran",            "全屏" },  // STR_W_SESSION_FULL
  { "Live",             "Live",              "Direct",                 "实时" },  // STR_W_LIVE_FOLLOW
  { "Angehalten",       "Paused",            "En pause",               "已暂停" },  // STR_W_LIVE_PAUSE
  { "Filter",           "Filter",            "Filtrer",                "筛选" },  // STR_W_LIVE_FILTER
  { "Kleinere Schrift", "Smaller text",      "Texte plus petit",       "缩小字体" },  // STR_W_LIVE_SMALLER
  { "Größere Schrift",  "Larger text",       "Texte plus grand",       "放大字体" },  // STR_W_LIVE_LARGER
  { "Vollbild beenden", "Leave full screen", "Quitter le plein écran", "退出全屏" },  // STR_W_SESSION_FULL_EXIT
  // The website's wish list, linked on the printer and the label page
  { "Drucker oder Etikettengröße fehlt? Hier wünschen", "Printer or label size missing? Request it",
    "Imprimante ou format d'étiquette manquant ? Demandez-le",
    "缺少打印机或标签尺寸？点此申请" },  // STR_W_P_WISH_LINK
  // The H3C's nine bay unit, by Bambu's own name
  { "AMS 3H", "AMS 3H", "AMS 3H", "AMS 3H" },  // STR_AMSV_UNIT_3H
  { "Tag nicht sicher gelesen. Spule kurz anheben und genauso wieder hinstellen.",
    "Tag not read reliably. Lift the spool briefly and put it back the same way.",
    "Tag mal lu. Soulevez un instant la bobine et reposez-la pareil.",
    "标签读取不稳定。请稍抬起料盘，再按原方向放回。" },  // STR_TAG2_UNCLEAR
  { "Tag wird noch gelesen. Spule bitte liegen lassen.",
    "Tag is still being read. Please leave the spool in place.",
    "Lecture du tag en cours. Laissez la bobine en place.",
    "正在读取标签，请勿移动料盘。" },  // STR_TAG2_READING
  // Remembered WiFi networks: the WiFi list, the saved networks screen and its popup
  { "gespeichert", "saved",
    "connu",
    "已保存" },  // STR_WIFI_KNOWN_WORD
  { "Gespeicherte Netze", "Saved networks",
    "Réseaux connus",
    "已保存网络" },  // STR_WIFI_SAVED_TITLE
  { "%d gespeichert", "%d saved",
    "%d connu(s)",
    "已存 %d 个" },  // STR_WIFI_SAVED_COUNT
  { "Verbunden, bevorzugt", "Connected, preferred",
    "Connecté, préféré",
    "已连接，首选" },  // STR_WIFI_ST_CONN_PREF
  { "Bevorzugt", "Preferred",
    "Préféré",
    "首选" },  // STR_WIFI_ST_PREFERRED
  { "Gespeichert", "Saved",
    "Connu",
    "已保存" },  // STR_WIFI_ST_SAVED
  { "Jetzt verbinden", "Connect now",
    "Se connecter",
    "立即连接" },  // STR_WIFI_CONNECT_NOW
  { "Vergessen", "Forget",
    "Oublier",
    "忽略" },  // STR_WIFI_FORGET
  { "Zum Vergessen erst ein anderes Netz wählen.", "To forget it, choose another network first.",
    "Pour l'oublier, choisissez un autre réseau.",
    "如需忽略，请先选择其他网络。" },  // STR_WIFI_PREF_KEEP
  { "Noch kein Netz gespeichert.", "No network saved yet.",
    "Aucun réseau connu.",
    "暂无已保存网络。" },  // STR_WIFI_SAVED_NONE
  // The WiFi card on the settings page in the browser
  { "In Reichweite", "In range",
    "À portée",
    "信号范围内" },  // STR_W_WIFI_INRANGE
  { "Netze suchen", "Find networks",
    "Rechercher les réseaux",
    "搜索网络" },  // STR_W_WIFI_SCAN_BTN
  { "offen", "open",
    "ouvert",
    "开放" },  // STR_W_WIFI_OPEN
  { "Verbinden", "Connect",
    "Se connecter",
    "连接" },  // STR_W_WIFI_CONNECT
  { "Mit %s verbinden?\nLiegt %s in einem anderen Netz als dieser Browser, verliert die Seite danach die Verbindung zur Waage.", "Connect to %s?\nIf %s is not the network this browser is on, the page loses the scale afterwards.",
    "Se connecter à %s ?\nSi %s n'est pas le réseau de ce navigateur, la page perdra ensuite la balance.",
    "连接到 %s？\n若 %s 与当前浏览器不在同一网络，切换后页面将与秤断开连接。" },  // STR_W_WIFI_ASK
  { "%s vergessen?\nDie Waage wechselt dann nicht mehr von selbst in dieses Netz.", "Forget %s?\nThe scale then no longer switches to this network by itself.",
    "Oublier %s ?\nLa balance ne passera plus d'elle-même sur ce réseau.",
    "忽略 %s？\n秤之后将不再自动切换至此网络。" },  // STR_W_WIFI_ASK_FORGET
  { "Die Waage versucht %s …", "The scale is trying %s …",
    "La balance essaie %s …",
    "秤正在尝试连接 %s …" },  // STR_W_WIFI_TRYING
  { "Liegt %s in einem anderen Netz, ist die Waage danach dort unter %s zu finden.", "If %s is another network, the scale is found there afterwards at %s.",
    "Si %s est un autre réseau, vous retrouverez ensuite la balance sous %s.",
    "若 %s 为其他网络，切换后可通过 %s 访问秤。" },  // STR_W_WIFI_AWAY_NAME
  { "Liegt %s in einem anderen Netz, steht die neue Adresse danach im WLAN-Menü der Waage.", "If %s is another network, the new address is shown in the scale's WiFi menu afterwards.",
    "Si %s est un autre réseau, la nouvelle adresse s'affichera ensuite dans le menu WiFi de la balance.",
    "若 %s 为其他网络，切换后可在秤的 WiFi 菜单中查看新地址。" },  // STR_W_WIFI_AWAY_MENU
  { "Verbunden mit %s. Es ist jetzt das bevorzugte Netz.", "Connected to %s. It is the preferred network now.",
    "Connectée à %s. C'est désormais le réseau préféré.",
    "已连接到 %s，现已设为首选网络。" },  // STR_W_WIFI_UP
  { "%s ging nicht, bitte Passwort und Reichweite prüfen. Die Waage ist wieder in %s.", "%s did not work, please check the password and the range. The scale is back on %s.",
    "%s n'a pas fonctionné, vérifiez le mot de passe et la portée. La balance est de retour sur %s.",
    "%s 连接失败，请检查密码与信号范围。秤已恢复连接至 %s。" },  // STR_W_WIFI_FAIL
  { "Keine Antwort mehr von der Waage. Sie ist jetzt wohl in %s.", "No answer from the scale any more. It is probably on %s now.",
    "La balance ne répond plus. Elle est sans doute maintenant sur %s.",
    "秤已无响应，当前可能已切换至 %s。" },  // STR_W_WIFI_GONE
  { "Ein neues Netz bekommt %d s. Klappt es nicht, bleibt die Waage im bisherigen Netz. Gespeicherte Passwörter verlassen die Waage nicht.", "A new network gets %d s. If it fails, the scale stays on the network it was on. Stored passwords never leave the scale.",
    "Un nouveau réseau dispose de %d s. En cas d'échec, la balance reste sur le réseau précédent. Les mots de passe enregistrés ne quittent jamais la balance.",
    "连接新网络限时 %d 秒。若连接失败，设备将保持原网络。已保存的密码绝不会离开设备。" },  // STR_W_WIFI_HINT
  { "Die Suche ist fehlgeschlagen. Bitte noch einmal.", "The search failed. Please try again.",
    "La recherche a échoué. Veuillez réessayer.",
    "搜索失败，请重试。" },  // STR_W_WIFI_SCAN_FAIL
  { "Die Waage ist gerade mit dem WLAN beschäftigt. Gleich noch einmal versuchen.", "The scale is busy with its WiFi. Please try again in a moment.",
    "La balance est occupée avec son WiFi. Réessayez dans un instant.",
    "设备 WiFi 正忙，请稍后再试。" },  // STR_W_WIFI_BUSY
  { "Tag-Formate", "Tag formats",
    "Formats de tag",
    "标签格式" },  // STR_W_C_TAG_FORMATS
  { "Netz wählen", "Choose a network",
    "Choisir un réseau",
    "选择网络" },  // STR_W_WIFI_PICK
  { "L", "L",
    "G",
    "L" },  // STR_AMSV_HOTEND_L
  { "R", "R",
    "D",
    "R" },  // STR_AMSV_HOTEND_R
  { "Druckt gerade", "Printing now",
    "Impression en cours",
    "正在打印" },  // STR_AMSD_PRINTING
  { "Im Drucker geladen", "Loaded in the printer",
    "Chargé dans l'imprimante",
    "已加载至打印机" },  // STR_AMSD_LOADED
  { "Druckt gerade, linkes Hotend", "Printing now, left hotend",
    "Impression en cours, buse gauche",
    "正在打印（左热端）" },  // STR_AMSD_PRINTING_LEFT
  { "Druckt gerade, rechtes Hotend", "Printing now, right hotend",
    "Impression en cours, buse droite",
    "正在打印（右热端）" },  // STR_AMSD_PRINTING_RIGHT
  { "Im linken Hotend geladen", "Loaded in the left hotend",
    "Chargé dans la buse gauche",
    "已加载至左热端" },  // STR_AMSD_LOADED_LEFT
  { "Im rechten Hotend geladen", "Loaded in the right hotend",
    "Chargé dans la buse droite",
    "已加载至右热端" },  // STR_AMSD_LOADED_RIGHT
  { "keiner", "none",
    "aucun",
    "无" },  // STR_OPT_PRICE_NONE
  { "Leerspule", "Empty spool",
    "Bobine vide",
    "空料盘" },  // STR_OPT_SPOOL
  { "gilt nur für diese Spule", "for this spool only",
    "pour cette bobine seule",
    "仅适用于此料盘" },  // STR_OPT_SPOOL_SUB
  { "Dichte", "Density",
    "Densité",
    "密度" },  // STR_OPT_DENSITY
  { "Fertig", "Done",
    "Terminé",
    "完成" },  // STR_OPT_DONE
  { "Welche Leerspule?", "Which empty spool?",
    "Quelle bobine vide ?",
    "选择空料盘" },  // STR_SPICK_TITLE
  { "Automatisch", "Automatic",
    "Automatique",
    "自动" },  // STR_SPICK_AUTO
  { "vom Tag", "from the tag",
    "du tag",
    "来自标签" },  // STR_SPICK_FROM_TAG
  { "aus der Datenbank", "from the database",
    "de la base",
    "来自数据库" },  // STR_SPICK_FROM_DB
  { "vom Filament", "from the filament",
    "du filament",
    "来自耗材" },  // STR_SPICK_FROM_FILAMENT
  { "von der Marke", "from the brand",
    "de la marque",
    "来自品牌" },  // STR_SPICK_FROM_VENDOR
  { "von der Vorlage", "from the template",
    "du modèle",
    "来自模板" },  // STR_SPICK_FROM_TEMPLATE
  { "nicht bekannt", "not known",
    "inconnu",
    "未知" },  // STR_SPICK_UNKNOWN
  { "zuletzt", "recent",
    "récent",
    "最近" },  // STR_SPICK_RECENT
  { "Eingegeben", "Typed in",
    "Saisi",
    "手动输入" },  // STR_SPICK_TYPED_NAME
  { "Hersteller", "Makers",
    "Fabricants",
    "厂商" },  // STR_SPICK_MAKERS
  { "Eingeben", "Type in",
    "Saisir",
    "手动输入" },  // STR_SPICK_TYPE_BTN
  { "Aus der SpoolmanDB. Eine Spule: Tippen übernimmt sie.", "From SpoolmanDB. One spool: a tap takes it.",
    "Issu de SpoolmanDB. Une bobine : un appui la prend.",
    "数据来自 SpoolmanDB，单款点击即选。" },  // STR_SPICK_MAKERS_HINT
  { "Die häufigste zuerst, aus der SpoolmanDB.", "The most common first, from SpoolmanDB.",
    "La plus courante d'abord (SpoolmanDB).",
    "来自 SpoolmanDB，常用优先。" },  // STR_SPICK_MAKER_HINT
  { "%d Spulen", "%d spools",
    "%d bobines",
    "%d 个料盘" },  // STR_SPICK_SPOOLS
  { "Spule", "Spool",
    "Bobine",
    "料盘" },  // STR_SPOOL_KIND_ANY
  { "Kunststoff", "Plastic",
    "Plastique",
    "塑料" },  // STR_SPOOL_KIND_PLASTIC
  { "Karton", "Cardboard",
    "Carton",
    "纸板" },  // STR_SPOOL_KIND_CARDBOARD
  { "Metall", "Metal",
    "Métal",
    "金属" },  // STR_SPOOL_KIND_METAL
  { "Leerspulen", "Empty spools",
    "Bobines vides",
    "空料盘" },  // STR_W_NAV_SPOOLS
  { "Eigene Leerspulen stehen an der Waage beim Anlegen einer Spule unter Optionen > Leerspule. Für Refills auf fremden Spulen, umgespultes Filament und selbst gedruckte Spulen.", "Your own empty spools appear on the scale when a spool is created, under Options > Empty spool. For refills on other makers' spools, respooled filament and printed spools.",
    "Vos bobines vides apparaissent sur la balance à la création d'une bobine, sous Options > Bobine vide. Pour les recharges sur la bobine d'une autre marque, le filament rebobiné et les bobines imprimées.",
    "创建料盘时，自定义空料盘会显示在称重台的“选项 > 空料盘”中，适用于跨品牌替换芯、重绕耗材及自印料盘。" },  // STR_W_SPOOLS_INTRO
  { "Name", "Name",
    "Nom",
    "名称" },  // STR_W_SPOOLS_NAME
  { "Leergewicht (g)", "Empty weight (g)",
    "Poids à vide (g)",
    "空盘重量 (g)" },  // STR_W_SPOOLS_WEIGHT
  { "z. B. Sunlu Karton", "e.g. Sunlu cardboard",
    "p. ex. Sunlu carton",
    "例如：Sunlu 纸盘" },  // STR_W_SPOOLS_NAME_PH
  { "Von der Waage", "From the scale",
    "De la balance",
    "从秤读取" },  // STR_W_SPOOLS_TAKE
  { "Von der Waage übernommen", "Taken from the scale",
    "Repris de la balance",
    "已从秤读取" },  // STR_W_SPOOLS_TAKEN
  { "Entfernen", "Remove",
    "Retirer",
    "移除" },  // STR_W_SPOOLS_REMOVE
  { "Leerspule hinzufügen", "Add empty spool",
    "Ajouter une bobine vide",
    "添加空料盘" },  // STR_W_SPOOLS_ADD
  { "%d von %d", "%d of %d",
    "%d sur %d",
    "%d / %d" },  // STR_W_SPOOLS_COUNT
  { "Waage leer: zum Übernehmen eine leere Spule auflegen", "Scale empty: put an empty spool on it to take its weight",
    "Balance vide : posez une bobine vide pour reprendre son poids",
    "秤盘为空：放上空料盘即可读取重量" },  // STR_W_SPOOLS_EMPTY
  { "Waage jetzt: %s", "Scale now: %s",
    "Balance : %s",
    "当前称重：%s" },  // STR_W_SPOOLS_NOW
  { "ruhig", "steady",
    "stable",
    "已稳定" },  // STR_W_SPOOLS_STEADY
  { "unruhig", "settling",
    "instable",
    "稳定中" },  // STR_W_SPOOLS_MOVING
  { "Jede Zeile braucht einen Namen (höchstens 31 Zeichen) und 10 bis 2000 g.", "Each row needs a name (31 characters at most) and 10 to 2000 g.",
    "Chaque ligne demande un nom (31 caractères au plus) et 10 à 2000 g.",
    "每行均需填写名称（最多 31 个字符）及 10 至 2000 g 的重量。" },  // STR_W_SPOOLS_INVALID
  { "Meine Spulen", "My spools",
    "Mes bobines",
    "我的料盘" },  // STR_SPICK_MINE
  { "Vom Server", "From the server",
    "Du serveur",
    "来自服务器" },  // STR_SPICK_SERVER
  { "Leerspule wählen", "Pick the empty spool",
    "Choisir la bobine vide",
    "选择空料盘" },  // STR_WP_PICK_EMPTY
  { "Aus der Liste, nur für diese Spule", "From the list, for this spool only",
    "Depuis la liste, pour cette bobine seule",
    "从列表选择，仅用于当前料盘" },  // STR_WP_PICK_EMPTY_SUB
  { "von dieser Spule", "from this spool",
    "de cette bobine",
    "来自此料盘" },  // STR_SPICK_FROM_SPOOL
  { "Kein Abzug", "No offset",
    "Sans retrait",
    "无扣重" },  // STR_SPICK_NO_OFFSET
  { "ungeprüft", "unchecked",
    "non vérifié",
    "未验证" },  // STR_PRN_MEDIA_UNCHECKED
  { "Andere Größe", "Other size",
    "Autre format",
    "其他尺寸" },  // STR_W_P_MEDIA_OTHER
  { "Breite", "Width",
    "Largeur",
    "宽度" },  // STR_W_P_MEDIA_WIDTH
  { "Länge", "Length",
    "Longueur",
    "长度" },  // STR_W_P_MEDIA_LENGTH
  { "Übernehmen", "Use",
    "Utiliser",
    "使用" },  // STR_W_P_MEDIA_USE
  { "Dieser Drucker nimmt %u bis %u mm Breite und %u bis %u mm Länge.", "This printer takes %u to %u mm across and %u to %u mm along.",
    "Cette imprimante accepte %u à %u mm de largeur et %u à %u mm de longueur.",
    "此打印机支持 %u 至 %u mm 宽、%u 至 %u mm 长的标签。" },  // STR_W_P_MEDIA_RANGE
  { "Geprüfte Größe.", "Checked size.",
    "Format vérifié.",
    "已验证尺寸。" },  // STR_W_P_MEDIA_ST_CHECKED
  { "Ungeprüft: Das Etikett wird für diese Größe berechnet. Sieh dir vor dem Druck die Vorschau unter Etiketten an.", "Unchecked: the label is worked out for this size. Look at the preview under Labels before you print.",
    "Non vérifié : l'étiquette est calculée pour ce format. Regardez l'aperçu sous Étiquettes avant d'imprimer.",
    "未验证：标签排版将按此尺寸自动计算，打印前请在“标签”中查看预览。" },  // STR_W_P_MEDIA_ST_UNCHECKED
  { "Diese Größe nimmt der Drucker nicht.", "The printer does not take this size.",
    "L'imprimante n'accepte pas ce format.",
    "打印机不支持此尺寸。" },  // STR_W_P_MEDIA_ST_RANGE
  { "Zu groß für den Speicher der Waage.", "Too large for the scale's memory.",
    "Trop grand pour la mémoire de la balance.",
    "超出秤的内存容量。" },  // STR_W_P_MEDIA_ST_LARGE
  { "Zu klein: Darauf passt kein Etikett mit Kopf und einer Zeile.", "Too small: no label fits on it with its header and one line.",
    "Trop petit : aucune étiquette n'y tient avec son en-tête et une ligne.",
    "尺寸过小：无法容纳标题及单行内容。" },  // STR_W_P_MEDIA_ST_SMALL
  { "Ungeprüfte Etikettgröße: Die Zeilenzahl ist berechnet. Prüf die Vorschau, bevor du druckst.", "Unchecked label size: the number of lines is worked out. Check the preview before you print.",
    "Format d'étiquette non vérifié : le nombre de lignes est calculé. Vérifiez l'aperçu avant d'imprimer.",
    "未验证的标签尺寸：行数已自动计算，打印前请检查预览。" },  // STR_W_LBL_UNCHECKED
  { "Farbe als", "Colour as",
    "Couleur en",
    "颜色显示为" },  // STR_W_L_COLOR_AS
  { "Hex-Code", "Hex code",
    "Code hex",
    "十六进制码" },  // STR_W_L_COLOR_HEX
  { "Name", "Name",
    "Nom",
    "名称" },  // STR_W_L_COLOR_NAME
  { "Name: Der Farbname wandert vom Ende des Titels in die Farbzeile. Ohne Farbnamen steht der Hex-Code.", "Name: the colour name moves from the end of the title to the colour line. Without one, the hex code is printed.",
    "Nom : le nom de couleur passe de la fin du titre à la ligne Couleur. Sans nom de couleur, le code hex est imprimé.",
    "名称：颜色名称将从标题末尾移至颜色行；若无颜色名称，则打印十六进制码。" },  // STR_W_L_COLOR_HINT
  { "Ungeprüfte Größe.", "Unchecked size.",
    "Format non vérifié.",
    "未验证尺寸。" },  // STR_W_P_MEDIA_ST_UNCHECKED_SHORT
};

StringID tagWriteResultString(uint8_t code) {
  switch (code) {
    case TW_OK:            return STR_TW_OK;
    case TW_ERR_NO_TAG:    return STR_TW_ERR_NO_TAG;
    case TW_ERR_NOT_NTAG:  return STR_TW_ERR_NOT_NTAG;
    case TW_ERR_BACKEND:   return STR_TW_ERR_BACKEND;
    case TW_ERR_SPACE:     return STR_TW_ERR_SPACE;
    case TW_ERR_OTHER_TAG: return STR_TW_ERR_OTHER_TAG;
    case TW_ERR_OTHER_TAG_WRITE: return STR_TW_ERR_OTHER_TAG_W;
    case TW_ERR_NOT_BLANK: return STR_TW_ERR_NOT_BLANK;
    default:               return STR_TW_ERR_WRITE;
  }
}

// Without this, a missing entry is not a compile error: every string from the
// gap onwards reads as the wrong one, in every language, and the only symptom
// is a UI that looks scrambled. That is what a merge produces when two
// branches both append here, and nothing else would catch it.
static_assert(sizeof(STRINGS) / sizeof(STRINGS[0]) == STR_COUNT,
              "STRINGS and the StringID enum are out of step");
