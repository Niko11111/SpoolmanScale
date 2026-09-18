// ============================================================
//  SpoolmanScale – Localization (i18n)
//  lang.cpp - String table DE / EN / FR
// ============================================================
#include <lvgl.h>
#include "services/tag_write.h"   // the TagWriteResult codes
#include "lang.h"

Lang   g_lang     = LANG_EN;
uint8_t g_date_fmt = 0;  // 0=DD.MM.YYYY  1=YYYY-MM-DD

// Order MUST exactly match the StringID enum in lang.h!
// Format: { "Deutsch", "English", "Francais" }
const char* const STRINGS[][3] = {

  // Navigation
  { "Abbrechen",        "Cancel",       "Annuler" },  // STR_CANCEL
  { "Zurück",           "Back",         "Retour" },  // STR_BACK
  { "Bestätigen",       "Confirm",      "Confirmer" },  // STR_CONFIRM
  { "Erneut versuchen", "Try again",    "Réessayer" },  // STR_RETRY
  { "ID neu eingeben",  "Enter new ID", "Ressaisir l'ID" },  // STR_ENTER_NEW_ID

  // Mainscreen Labels
  { "Spoolman",         "Spoolman",    "Spoolman" },  // STR_LBL_SPOOLMAN
  { "Waage",            "Scale",       "Balance" },  // STR_LBL_SCALE
  { "Letzte Benutzung", "Last used",   "Dernier usage" },  // STR_LBL_LAST_USED
  { "Letzte Trocknung", "Last dried",  "Dernier séchage" },  // STR_LBL_LAST_DRIED
  { "Temperatur",       "Temperature", "Température" },  // STR_LBL_TEMP
  { "Hersteller",       "Vendor",      "Fabricant" },  // STR_LBL_VENDOR

  // Mainscreen Status
  { "Spule an Reader halten...",    "Hold spool near reader...",    "Présentez la bobine..." },  // STR_WAIT_SCAN
  { "NFC Tag erkannt",              "NFC tag detected",             "Tag NFC détecté" },  // STR_TAG_FOUND
  { "Kein WLAN",                    "No WiFi",                      "Pas de WiFi" },  // STR_NO_WIFI
  { "Warte...",                     "Please wait...",               "Patientez..." },  // STR_WAIT
  { "Warte auf Scan...",            "Waiting for scan...",          "Attente du scan..." },  // STR_WAIT_SCAN_SM
  { "unbekannt",                    "unknown",                      "inconnu" },  // STR_UNKNOWN
  { "nicht lesbar",                 "not readable",                 "illisible" },  // STR_NOT_READABLE
  { "heute",                        "today",                        "aujourd'hui" },  // STR_TODAY
  { "gestern",                      "yesterday",                    "hier" },  // STR_YESTERDAY
  { "vor %d Tagen",                 "%d days ago",                  "il y a %d jours" },  // STR_DAYS_AGO
  { "Fehler beim Speichern",        "Error saving",                 "Échec de sauvegarde" },  // STR_ERR_SAVE
  { "Nicht in Spoolman",            "Not in Spoolman",              "Hors Spoolman" },  // STR_NOT_IN_SPOOLMAN
  { "Archiviert",                   "Archived",                     "Archivée" },  // STR_ARCHIVED
  { "Lese Tag...",                  "Reading tag...",               "Lecture du tag..." },  // STR_READING_TAG
  { "Durchsuche Inventar...", "Searching inventory...",
    "Parcours de l'inventaire..." },  // STR_SEARCHING_INVENTORY
  { "Durchsuche Inventar... %u KB", "Searching inventory... %u KB",
    "Parcours de l'inventaire... %u ko" },  // STR_SEARCHING_INVENTORY_KB

  // Mainscreen Buttons
  { "Gewicht updaten",  "Update Weight", "Envoyer le poids" },  // STR_BTN_WEIGHT
  { "Heute getrocknet", "Dried today",   "Noter le séchage" },  // STR_BTN_DRIED
  { "Spule verknüpfen", "Link Spool",    "Lier la bobine" },  // STR_BTN_LINK

  // Welcome Screen

  // WiFi Setup
  { "WLAN einrichten",          "WiFi setup",           "Réglage du WiFi" },  // STR_WIFI_TITLE
  { "Netzwerke suchen...",      "Scanning networks...", "Recherche des réseaux..." },  // STR_WIFI_SCAN
  { "Keine Netzwerke gefunden", "No networks found",    "Aucun réseau trouvé" },  // STR_WIFI_NO_NET
  { "WLAN-Passwort",            "WiFi password",        "Mot de passe WiFi" },  // STR_WIFI_PASS_TITLE
  { "Passwort für: %s",         "Password for: %s",     "Pour le réseau %s" },  // STR_WIFI_PASS_HINT
  { "Passwort...",              "Password...",          "Mot de passe..." },  // STR_WIFI_PASS_PLACEHOLDER
  { "Verbinde mit %s...",       "Connecting to %s...",  "Connexion à %s..." },  // STR_WIFI_CONNECTING
  { "Verbunden!",               "Connected!",           "Connecté !" },  // STR_WIFI_SUCCESS

  // Spoolman IP
  { "Spoolman Server", "Spoolman Server", "Serveur Spoolman" },  // STR_SPOOLMAN_TITLE

  // Settings
  { "Einstellungen",               "Settings",                 "Réglages" },  // STR_SETTINGS_TITLE
  { "Verbindung",                  "Connection",               "Connexion" },  // STR_TILE_CONNECTION
  { "WLAN & Server",               "WiFi & server",            "WiFi et serveur" },  // STR_TILE_CONN_SUB
  { "Waage",                       "Scale",                    "Balance" },  // STR_TILE_SCALE
  { "Kalibrieren | Beutel | Mehr", "Calibrate | Bag | More",   "Étalonnage | Sachet | Plus" },  // STR_TILE_SCALE_SUB
  { "Display",                     "Display",                  "Affichage" },  // STR_TILE_DISPLAY
  { "Helligkeit & Timeout",        "Brightness & Timeout",     "Luminosité et veille" },  // STR_TILE_DISPLAY_SUB
  { "System",                      "System",                   "Système" },  // STR_TILE_SYSTEM
  { "Sprache | Update | Info", "Language | Update | Info",
    "Langue | Mise à jour | Info" },  // STR_TILE_SYSTEM_SUB

  // Connection
  { "WLAN-Einstellungen", "WiFi settings",     "Réglages WiFi" },  // STR_BTN_WIFI_SETTINGS
  { "Nicht konfiguriert", "Not configured",    "Non configuré" },  // STR_BTN_WIFI_NONE
  { "WLAN-Status",        "WiFi status",       "État du WiFi" },  // STR_BTN_WIFI_STATUS
  { "Nicht verbunden",    "Not connected",     "Sans connexion" },  // STR_BTN_WIFI_STATUS_SUB
  { "Server, OTA, Logs",  "Server, OTA, logs", "Serveur, OTA, journaux" },  // STR_BTN_WEB_SUB
  { "Webserver",          "Web server",        "Serveur web" },  // STR_WEB_SERVER
  { "Wartung",            "Maintenance",       "Maintenance" },  // STR_WEB_MAINT
  { "Einstellungen",      "Settings",          "Réglages" },  // STR_WEB_CONFIG
  { "Aus: Port 80 antwortet nicht.",
    "Off: nothing answers on port 80.",
    "Désactivé : inaccessible depuis le navigateur." },  // STR_WEB_SERVER_HINT
  { "Schaltet die Weboberfläche im Netz an und aus. Ausgeschaltet antwortet Port 80 nicht mehr - außer FilaMan hat ein Geräte-Token hinterlegt, dann bleibt allein dessen Tag-Auslöser erreichbar.",
    "Turns the web interface on and off across the network. Switched off, port 80 stops answering - unless FilaMan holds a device token, in which case only its tag trigger stays reachable.",
    "Active ou désactive l'interface web sur le réseau. Désactivée, elle ne répond plus (port 80) - sauf avec FilaMan, si la balance y est associée : seules les lectures et écritures de tag demandées par FilaMan restent alors possibles." },  // STR_WEB_SERVER_INFO
  { "Liefert Firmware-Upload, Logs, Neustart und das Tag-Schreiben. Standardmäßig aus: schreibt Firmware und NFC-Tags, ohne Passwort.",
    "Serves firmware upload, logs, restart and tag writing. Off by default: these write firmware and NFC tags, with no password.",
    "Rend accessibles dans le navigateur l'envoi de firmware, les journaux, le redémarrage et l'écriture de tags. Désactivé par défaut : sans mot de passe, tout appareil du réseau pourrait installer un firmware et écrire des tags NFC." },  // STR_WEB_MAINT_HINT
  { "Firmware, Logs, Tags, Neustart",
    "Firmware, logs, tags, restart",
    "Firmware, journaux, tags, redémarrage" },  // STR_WEB_MAINT_SUB
  { "Liefert Listenlimits, Trocknung, Anzeige und die Backend-Zugangsdaten. Standardmäßig aus: ändert Einstellungen ohne Passwort.",
    "Serves list limits, drying, display and the backend credentials. Off by default: changes settings with no password.",
    "Rend accessibles dans le navigateur les limites de liste, le séchage, l'affichage et les identifiants du backend. Désactivé par défaut : sans mot de passe, tout appareil du réseau pourrait modifier les réglages." },  // STR_WEB_CONFIG_HINT
  { "Listenlimits, Trocknung, Anzeige",
    "List limits, drying, display",
    "Limites de liste, séchage, affichage" },  // STR_WEB_CONFIG_SUB

  // Scale
  { "Waage",         "Scale",       "Balance" },  // STR_SCALE_TITLE
  { "Kalibrierung",  "Calibration", "Étalonnage" },  // STR_BTN_CALIBRATE
  { "Beutelgewicht", "Bag weight",  "Poids du sachet" },  // STR_BTN_BAGWEIGHT

  // Calibration
  { "Kalibrierung",             "Calibration",              "Étalonnage" },  // STR_CAL_TITLE
  { "Faktor: --",               "Factor: --",               "Facteur : --" },  // STR_CAL_FACTOR
  { "Faktor: %.4f",             "Factor: %.4f",             "Facteur : %.4f" },  // STR_CAL_OK
  { "Fehler: Gewicht = 0",      "Error: weight = 0",        "Erreur : poids = 0" },  // STR_CAL_ZERO_ERR
  { LV_SYMBOL_OK "  Berechnen", LV_SYMBOL_OK "  Calculate", LV_SYMBOL_OK "  Calculer" },  // STR_BTN_CALCULATE

  // Bag weight
  { "Vakuumbeutel inkl. Silikagelpack (in Gramm)",
    "Vacuum bag incl. silica gel pack (in grams)",
    "Sachet sous vide, gel de silice compris (en grammes)" },  // STR_BAG_DESC
  { "%.1fg gespeichert", "%.1fg saved",   "%.1fg enregistré" },  // STR_BAG_SAVED
  { "Ungültiger Wert",   "Invalid value", "Valeur invalide" },  // STR_BAG_INVALID

  // Display
  { "Display", "Display", "Affichage" },  // STR_DISPLAY_TITLE
  { LV_SYMBOL_IMAGE "  Helligkeit",
    LV_SYMBOL_IMAGE "  Brightness",
    LV_SYMBOL_IMAGE "  Luminosité" },  // STR_BRIGHT_LABEL
  { LV_SYMBOL_EYE_OPEN "  Dimmen nach (Min.)",
    LV_SYMBOL_EYE_OPEN "  Dim after (min.)",
    LV_SYMBOL_EYE_OPEN "  Atténuer après (min)" },  // STR_DIM_LABEL
  { LV_SYMBOL_POWER "  Tiefschlaf nach (Min.)",
    LV_SYMBOL_POWER "  Deep sleep after (min.)",
    LV_SYMBOL_POWER "  Veille profonde après (min)" },  // STR_SLEEP_LABEL

  // System
  { "System", "System",
    "Système" },  // STR_SYSTEM_TITLE
  { "Deutsch / English", "Deutsch / English",
    "Deutsch / English / Français" },  // STR_BTN_LANG_SUB
  { "Firmware Update", "Firmware Update",
    "Mise à jour firmware" },  // STR_BTN_FW_UPDATE
  { "Browser oder GitHub", "Browser or GitHub",
    "Navigateur ou GitHub" },  // STR_BTN_FW_SUB
  { "Info & Unterstützung", "Info & Support",
    "Info et soutien" },  // STR_BTN_INFO
  { "Ko-fi - GitHub - Discord - MakerWorld", "Ko-fi - GitHub - Discord - MakerWorld",
    "Ko-fi - GitHub - Discord - MakerWorld" },  // STR_BTN_INFO_SUB

  // Language screen
  { "Sprache / Language", "Sprache / Language", "Langue / Language" },  // STR_LANG_TITLE
  { "Gerät startet nach Auswahl neu.",
    "Device will reboot after selection.",
    "Choisir une langue ou un format de date redémarre l'appareil." },  // STR_LANG_HINT
  { "Datum / Date format:", "Datum / Date format:", "Format de date :" },  // STR_DATE_FMT_LABEL

  // OTA
  { "Firmware Update", "Firmware Update",
    "Mise à jour firmware" },  // STR_OTA_TITLE
  { "Upload via Webbrowser", "Upload via web browser",
    "Envoi par navigateur web" },  // STR_OTA_BROWSER
  { ".bin vom PC + SD-Logging", "Upload from PC + SD logging",
    "Depuis le PC + journal SD" },  // STR_OTA_BROWSER_SUB
  { "Update via GitHub", "Update via GitHub",
    "Mise à jour par GitHub" },  // STR_OTA_GITHUB
  { "Direkt-Update aus GitHub Releases", "Direct update from GitHub Releases",
    "Mise à jour directe depuis GitHub Releases" },  // STR_OTA_GITHUB_SUB
  { "Browser Update", "Browser Update",
    "Mise à jour par navigateur" },  // STR_OTA_BROWSER_TITLE
  { LV_SYMBOL_WARNING "  Kein WiFi\nBitte zuerst WiFi einrichten.",
    LV_SYMBOL_WARNING "  No WiFi\nPlease set up WiFi first.",
    LV_SYMBOL_WARNING "  Pas de WiFi\nConfigurez d'abord le WiFi." },  // STR_OTA_NO_WIFI
  { "Browser öffnen und aufrufen:",
    "Open browser and go to:",
    "Ouvrez un navigateur et allez à :" },  // STR_OTA_OPEN_BROWSER
  { "Datei auswählen: SpoolmanScale vX.Y.Z.bin",
    "Select file: SpoolmanScale vX.Y.Z.bin",
    "Choisissez le fichier : SpoolmanScale vX.Y.Z.bin" },  // STR_OTA_FILE_HINT
  { LV_SYMBOL_WIFI "  Warte auf Upload...",
    LV_SYMBOL_WIFI "  Waiting for upload...",
    LV_SYMBOL_WIFI "  Attente de l'envoi..." },  // STR_OTA_WAITING
  { LV_SYMBOL_DOWNLOAD "  Lade hoch...",
    LV_SYMBOL_DOWNLOAD "  Uploading...",
    LV_SYMBOL_DOWNLOAD "  Envoi en cours..." },  // STR_OTA_UPLOADING
  { LV_SYMBOL_OK "  Update OK! Starte neu...",
    LV_SYMBOL_OK "  Update OK! Restarting...",
    LV_SYMBOL_OK "  Mise à jour OK ! Redémarrage..." },  // STR_OTA_SUCCESS
  { LV_SYMBOL_WARNING "  Update fehlgeschlagen",
    LV_SYMBOL_WARNING "  Update failed",
    LV_SYMBOL_WARNING "  Échec de la mise à jour" },  // STR_OTA_FAIL
  { LV_SYMBOL_CLOSE "  Server stoppen",
    LV_SYMBOL_CLOSE "  Stop server",
    LV_SYMBOL_CLOSE "  Arrêter le serveur" },  // STR_BTN_STOP_SERVER
  { "Aktuell: %s", "Current: %s", "Actuelle : %s" },  // STR_OTA_CURRENT

  // Info Screen
  { "SpoolmanScale  %s", "SpoolmanScale  %s", "SpoolmanScale  %s" },  // STR_INFO_VERSION
  { "Tippe einen Button um den QR-Code anzuzeigen.",
    "Tap a button to show the QR code.",
    "Touchez un bouton pour afficher le QR code." },  // STR_INFO_HINT

  // QR Popups
  { "Projekt gefällt dir? Kauf mir einen Kaffee!",
    "Support this project!",
    "Le projet vous plaît ? Offrez-moi un café !" },  // STR_QR_KOFI_DESC
  { "Quellcode, Releases & Dokumentation",
    "Source code, releases & docs",
    "Code source, versions et documentation" },  // STR_QR_GITHUB_DESC
  { "Community, Fragen & Support",
    "Community, questions & support",
    "Communauté, questions et entraide" },  // STR_QR_DISCORD_DESC
  { "3D-Modelle & Designs auf MakerWorld",
    "3D models & designs on MakerWorld",
    "Modèles 3D et créations sur MakerWorld" },  // STR_QR_MAKER_DESC

  // Weight popup
  { "Heute getrocknet\nspeichern?", "Save dried\ntoday?",
    "Enregistrer le séchage\nd'aujourd'hui ?" },  // STR_POPUP_DRIED_Q
  { "Gewicht in\nSpoolman updaten?", "Update weight\nin Spoolman?",
    "Mettre le poids à jour\ndans Spoolman ?" },  // STR_POPUP_WEIGHT_Q
  { "Leere Spule\n(Spule + Kern messen)", "Empty spool\n(measure spool + core)",
    "Bobine vide\n(mesurer bobine + moyeu)" },  // STR_BTN_EMPTY_SPOOL
  { "Ja, bestätigen", "Yes, confirm",
    "Oui, confirmer" },  // STR_BTN_CONFIRMED

  // Spool weight sub-popup
  { "Spulengewicht: %.0f g speichern als...",
    "Save spool weight: %.0f g as...",
    "Poids à vide %.0f g : enregistrer pour..." },  // STR_SPOOL_WEIGHT_TITLE
  { "Diese Spule\n(spool_weight)", "This spool\n(spool_weight)",
    "Cette bobine\n(spool_weight)" },  // STR_BTN_THIS_SPOOL
  { "Dieses Filament\n(spool_weight)", "This filament\n(spool_weight)",
    "Ce filament\n(spool_weight)" },  // STR_BTN_THIS_FILAMENT
  { "Hersteller\n(empty_spool_weight)", "Vendor\n(empty_spool_weight)",
    "Fabricant\n(empty_spool_weight)" },  // STR_BTN_THIS_VENDOR

  // Link Flow
  { "Bambu-Spule verknüpfen", "Link Bambu spool",  "Lier une bobine Bambu" },  // STR_LINK_BAMBU_TITLE
  { "Unbekannte Spule",       "Unknown spool",     "Bobine inconnue" },  // STR_LINK_NTAG_TITLE
  { "Spool-ID eingeben",      "Enter Spool-ID",    "Saisir l'ID de bobine" },  // STR_BTN_ENTER_ID
  { "Aus Liste wählen",       "Choose from list",  "Choisir dans la liste" },  // STR_BTN_FROM_LIST
  { "Spoolman Spool-ID",      "Spoolman Spool-ID", "ID de bobine Spoolman" },  // STR_LINK_ID_TITLE
  { "Prüfe...",               "Checking...",       "Vérification..." },  // STR_LINK_CHECKING
  { "ID nicht gefunden",      "ID not found",      "ID introuvable" },  // STR_LINK_ID_NOT_FOUND
  { "HTTP Fehler %d",         "HTTP Error %d",     "Erreur HTTP %d" },  // STR_LINK_HTTP_ERR
  { "JSON Fehler",            "JSON error",        "Erreur JSON" },  // STR_LINK_JSON_ERR
  { "Kein WLAN",              "No WiFi",           "Pas de WiFi" },  // STR_LINK_NO_WIFI
  { LV_SYMBOL_WARNING "  Spule bereits verknüpft",
    LV_SYMBOL_WARNING "  Tag already assigned!",
    LV_SYMBOL_WARNING "  Bobine déjà liée" },  // STR_WARN_A_TITLE
  { LV_SYMBOL_WARNING "  Trotzdem verknüpfen",
    LV_SYMBOL_WARNING "  Link anyway",
    LV_SYMBOL_WARNING "  Lier quand même" },  // STR_BTN_OVERWRITE
  { "Material stimmt nicht überein", "Material mismatch", "Le matériau ne correspond pas" },  // STR_WARN_B_TITLE
  { "Tag:      %s\nSpoolman: %s  (#%d)\n\nFalsche ID? Bitte nochmal prüfen.",
    "Tag:      %s\nSpoolman: %s  (#%d)\n\nWrong ID? Please double-check.",
    "Tag :      %s\nSpoolman : %s  (#%d)\n\nMauvais ID ? Vérifiez-le." },  // STR_WARN_B_DETAILS
  { "Hersteller wählen  (%d Spulen)", "Choose vendor  (%d spools)",
    "Choisir le fabricant  (%d bobines)" },  // STR_VENDOR_TITLE
  { "Material wählen",                "Choose material",            "Choisir le matériau" },  // STR_MAT_TITLE
  { "Keine Spulen ohne Tag\nin Spoolman gefunden.",
    "No unlinked spools\nfound in Spoolman.",
    "Aucune bobine sans tag\ntrouvée dans Spoolman." },  // STR_NO_VENDORS
  { "Keine Materialien gefunden.", "No materials found.",
    "Aucun matériau trouvé." },  // STR_NO_MATERIALS
  { "Keine passenden Spulen.\nBitte per ID verlinken.", "No matching spools.\nPlease link via ID.",
    "Aucune bobine correspondante.\nLiez la bobine par son ID." },  // STR_NO_SPOOLS
  { "Verknüpfen?", "Link this spool?",
    "Lier cette bobine ?" },  // STR_CONFIRM_LINK
  { LV_SYMBOL_OK "  Verknüpfen", LV_SYMBOL_OK "  Link",
    LV_SYMBOL_OK "  Lier" },  // STR_LINK_OK

  // Tare
  { LV_SYMBOL_OK "  Tare gesetzt!", LV_SYMBOL_OK "  Tare set!", LV_SYMBOL_OK "  Tare faite !" },  // STR_TARE_OK
  { LV_SYMBOL_WARNING "  Waage nicht bereit",
    LV_SYMBOL_WARNING "  Scale not ready",
    LV_SYMBOL_WARNING "  Balance non prête" },  // STR_TARE_NOT_READY
  { "API Fehler", "API Error", "Erreur d'API" },  // STR_API_ERROR

  // Reboot popup
  { "Neustart erforderlich", "Restart required", "Redémarrage nécessaire" },  // STR_REBOOT_TITLE
  { "Einstellung wird nach\ndem Neustart aktiv.",
    "Setting takes effect\nafter restart.",
    "Le réglage s'applique après\nle redémarrage." },  // STR_REBOOT_MSG
  { LV_SYMBOL_REFRESH "  Jetzt neu starten",
    LV_SYMBOL_REFRESH "  Restart now",
    LV_SYMBOL_REFRESH "  Redémarrer" },  // STR_REBOOT_BTN

  // WiFi connecting result
  { LV_SYMBOL_WARNING "  Verbindung fehlgeschlagen.\nSSID: %s",
    LV_SYMBOL_WARNING "  Connection failed.\nSSID: %s",
    LV_SYMBOL_WARNING "  Échec de la connexion.\nSSID : %s" },  // STR_WIFI_CONN_FAILED

  // WiFi quality
  { "Ausgezeichnet", "Excellent",    "Excellent" },  // STR_WIFI_QUAL_EXCELLENT
  { "Gut",           "Good",         "Bon" },  // STR_WIFI_QUAL_GOOD
  { "Mittel",        "Medium",       "Moyen" },  // STR_WIFI_QUAL_MEDIUM
  { "Schwach",       "Weak",         "Faible" },  // STR_WIFI_QUAL_WEAK
  { "Verbunden",     "Connected",    "Connecté" },  // STR_WIFI_STATUS_CONNECTED
  { "Getrennt",      "Disconnected", "Déconnecté" },  // STR_WIFI_STATUS_DISCONNECTED

  // Numpad buttons
  { LV_SYMBOL_OK "  Speichern", LV_SYMBOL_OK "  Save", LV_SYMBOL_OK "  Enregistrer" },  // STR_BTN_SAVE

  // Spool list title
  { "Alle", "All", "Toutes" },  // STR_SPOOLS_ALL

  // Settings calibration sub
  { "Faktor: %.2f", "Factor: %.2f", "Facteur : %.2f" },  // STR_CAL_FACTOR_SHORT

  // Archive confirm
  { "Spule wirklich\narchivieren?", "Really archive\nthis spool?",
    "Voulez-vous vraiment\narchiver cette bobine ?" },  // STR_ARCHIVE_CONFIRM

  // Weight popup archive button
  { LV_SYMBOL_CLOSE " leer / Archivieren\nremaining=0",
    LV_SYMBOL_CLOSE " empty / Archive\nremaining=0",
    LV_SYMBOL_CLOSE " vide / Archiver\nremaining=0" },  // STR_BTN_ARCHIVE_EMPTY

  // Welcome language select screen
  { "Sprache und Zeitzone", "Language and time zone", "Langue et fuseau horaire" },  // STR_WELCOME_LANG_TITLE
  { "Beides lässt sich später in den Einstellungen ändern.\nWeiter startet das Gerät einmal neu.",
    "Both can be changed later in Settings.\nNext restarts the device once.",
    "Langue et fuseau horaire restent modifiables dans les réglages.\nSuivant enregistre les deux choix et redémarre l'appareil une fois." },  // STR_WELCOME_LANG_HINT

  // WiFi scan count
  { "%d Netzwerke gefunden", "%d networks found", "%d réseaux trouvés" },  // STR_WIFI_NETWORKS_FOUND

  // Bag weight current label
  { "Aktuell: %.0f g", "Current: %.0f g", "Actuel : %.0f g" },  // STR_BAG_CURRENT

  // Warn popup A fields
  { "Spule #%d  |  %s %s\nAkt. Tag: %s",
    "Spool #%d  |  %s %s\nCur. tag: %s",
    "Bobine #%d  |  %s %s\nTag : %s" },  // STR_WARN_A_SPOOL_INFO
  { "Spule #%d\nAkt. Tag: %s",
    "Spool #%d\nCur. tag: %s",
    "Bobine #%d\nTag : %s" },  // STR_WARN_A_SPOOL_SHORT

  // Link entry context
  { "%s | nicht in Spoolman", "%s | not in Spoolman", "%s | absente de Spoolman" },  // STR_LINK_CTX_NOT_IN_SM

  // Weight popup buttons (with snprintf)
  { LV_SYMBOL_OK " Ohne Beutel\n%.0fg",
    LV_SYMBOL_OK " No bag\n%.0fg",
    LV_SYMBOL_OK " Sans sachet\n%.0fg" },  // STR_BTN_NO_BAG_VAL
  { LV_SYMBOL_OK " Mit Beutel\n%.0fg - %.0fg",
    LV_SYMBOL_OK " With bag\n%.0fg - %.0fg",
    LV_SYMBOL_OK " Avec sachet\n%.0fg - %.0fg" },  // STR_BTN_WITH_BAG_VAL
  { LV_SYMBOL_PLUS " Neue Spule\n%.0fg netto",
    LV_SYMBOL_PLUS " New spool\n%.0fg net",
    LV_SYMBOL_PLUS " Nouvelle bobine\n%.0fg net" },  // STR_BTN_NEW_SPOOL_VAL

  // First boot welcome screen
  { "Willkommen!",
    "Welcome!",
    "Bienvenue !" },  // STR_FIRSTBOOT_TITLE
  { "Deine SpoolmanScale ist fast bereit.",
    "Your SpoolmanScale is almost ready.",
    "Votre SpoolmanScale est presque prête." },  // STR_FIRSTBOOT_SUB
  // Both backends are named here because this screen appears before the user
  // has chosen one. It must therefore not go through backendText().
  { "In wenigen Schritten richten wir\nWLAN, Server und die Waage ein.",
    "In a few steps we will set up\nWiFi, the server and the scale.",
    "En quelques étapes, nous allons configurer\nle WiFi, le serveur et la balance." },  // STR_FIRSTBOOT_HINT
  { LV_SYMBOL_RIGHT "  Los geht's",
    LV_SYMBOL_RIGHT "  Get started",
    LV_SYMBOL_RIGHT "  C'est parti" },  // STR_FIRSTBOOT_BTN

  // Extra fields screen
  { "Spoolman Extra-Felder",
    "Spoolman Extra Fields",
    "Champs supplémentaires Spoolman" },  // STR_EXTRA_FIELDS_TITLE
  { "Prüfen...",
    "Checking...",
    "Vérification..." },  // STR_EXTRA_FIELDS_CHECKING
  { LV_SYMBOL_OK "  Vorhanden: %s",
    LV_SYMBOL_OK "  Present: %s",
    LV_SYMBOL_OK "  Présents : %s" },  // STR_EXTRA_FIELDS_ALL_OK
  { LV_SYMBOL_WARNING "  Fehlende Felder: %s",
    LV_SYMBOL_WARNING "  Missing fields: %s",
    LV_SYMBOL_WARNING "  Champs manquants : %s" },  // STR_EXTRA_FIELDS_MISSING
  { LV_SYMBOL_PLUS "  Fehlende Felder anlegen",
    LV_SYMBOL_PLUS "  Create missing fields",
    LV_SYMBOL_PLUS "  Créer les champs manquants" },  // STR_EXTRA_FIELDS_CREATE_BTN
  { "Felder anlegen?",
    "Create fields?",
    "Créer les champs ?" },  // STR_EXTRA_FIELDS_CONFIRM_TITLE
  { "SpoolmanScale legt die fehlenden\nExtra-Felder in Spoolman an.\n\nFortfahren?",
    "SpoolmanScale will create the\nmissing extra fields in Spoolman.\n\nProceed?",
    "SpoolmanScale va créer les champs\nsupplémentaires manquants dans Spoolman.\n\nContinuer ?" },  // STR_EXTRA_FIELDS_CONFIRM_MSG
  { "Lege Felder an...",
    "Creating fields...",
    "Création des champs..." },  // STR_EXTRA_FIELDS_CREATING
  { LV_SYMBOL_WARNING "  Fehler beim Anlegen: %s",
    LV_SYMBOL_WARNING "  Error creating: %s",
    LV_SYMBOL_WARNING "  Échec de la création : %s" },  // STR_EXTRA_FIELDS_CREATE_FAIL
  { LV_SYMBOL_WARNING "  Kein WiFi",
    LV_SYMBOL_WARNING "  No WiFi",
    LV_SYMBOL_WARNING "  Pas de WiFi" },  // STR_EXTRA_FIELDS_NO_WIFI
  { LV_SYMBOL_WARNING "  Kein Spoolman konfiguriert",
    LV_SYMBOL_WARNING "  No Spoolman configured",
    LV_SYMBOL_WARNING "  Aucun Spoolman configuré" },  // STR_EXTRA_FIELDS_NO_SPOOLMAN
  { "Überspringen",
    "Skip",
    "Ignorer" },  // STR_EXTRA_FIELDS_SKIP

  // Calibration reminder screen
  { "Waage kalibrieren",
    "Calibrate scale",
    "Étalonner la balance" },  // STR_CAL_REMINDER_TITLE
  { "Für genaue Messungen muss die Waage\nkalibriert werden.\n\nLege ein bekanntes Gewicht auf\nund gehe zu Einstellungen > Waage\n> Kalibrierung.\n\nDies kann auch später gemacht werden.",
    "For accurate measurements the scale\nneeds to be calibrated.\n\nPlace a known weight on the scale\nand go to Settings > Scale > Calibration.\n\nYou can also do this later.",
    "Pour des mesures précises, la balance\ndoit être étalonnée.\n\nPrévoyez un objet de poids connu\npuis allez dans Réglages > Balance\n> Étalonnage.\n\nVous pouvez aussi le faire plus tard." },  // STR_CAL_REMINDER_MSG
  { "Verstanden",
    "Got it!",
    "Compris" },  // STR_CAL_REMINDER_LATER
  { LV_SYMBOL_EDIT "  Jetzt kalibrieren",
    LV_SYMBOL_EDIT "  Calibrate now",
    LV_SYMBOL_EDIT "  Étalonner" },  // STR_CAL_REMINDER_NOW

  // Calibration TARE hint
  { "Erst TARE ohne Gewicht, dann Gewicht auflegen und berechnen.",
    "First TARE with nothing on the pad, then place the weight and calculate.",
    "Plateau vide, appuyez sur TARE, puis posez le poids et calculez." },  // STR_CAL_TARE_HINT

  // Extra fields test button
  { LV_SYMBOL_EDIT "  Testfeld erstellen",
    LV_SYMBOL_EDIT "  Generate test field",
    LV_SYMBOL_EDIT "  Créer un champ de test" },  // STR_EF_TEST_BTN
  { LV_SYMBOL_OK "  'spoolscale_test' erstellt!\nIn Spoolman nach dem Test löschen.",
    LV_SYMBOL_OK "  'spoolscale_test' created!\nDelete it in Spoolman after testing.",
    LV_SYMBOL_OK "  'spoolscale_test' créé !\nÀ supprimer dans Spoolman après le test." },  // STR_EF_TEST_CREATED
  { LV_SYMBOL_WARNING "  Feld existiert bereits in Spoolman.",
    LV_SYMBOL_WARNING "  Field already exists in Spoolman.",
    LV_SYMBOL_WARNING "  Le champ existe déjà dans Spoolman." },  // STR_EF_TEST_EXISTS
  { LV_SYMBOL_WARNING "  Testfeld konnte nicht erstellt werden.",
    LV_SYMBOL_WARNING "  Test field creation failed.",
    LV_SYMBOL_WARNING "  Le champ de test n'a pas pu être créé." },  // STR_EF_TEST_FAIL

  // Spoolman IP validation
  { "Verbindung wird geprüft...",
    "Testing connection...",
    "Test de la connexion..." },  // STR_SPOOLMAN_TESTING
  { LV_SYMBOL_WARNING "  Spoolman nicht erreichbar",
    LV_SYMBOL_WARNING "  Spoolman not reachable",
    LV_SYMBOL_WARNING "  Spoolman injoignable" },  // STR_SPOOLMAN_FAIL
  { "Erneut versuchen",
    "Retry",
    "Réessayer" },  // STR_SPOOLMAN_RETRY
  { "Überspringen",
    "Skip",
    "Ignorer" },  // STR_SPOOLMAN_SKIP

  // More info filament screen
  { "Mehr Info",
    "More info",
    "Plus d'infos" },  // STR_BTN_MORE_INFO

  // GitHub OTA check screen
  { "GitHub Update",
    "GitHub Update",
    "Mise à jour GitHub" },  // STR_GH_OTA_TITLE
  { "Auf Updates prüfen",
    "Check for Updates",
    "Rechercher des mises à jour" },  // STR_GH_OTA_CHECK_BTN
  { "Prüfen...",
    "Checking...",
    "Recherche..." },  // STR_GH_OTA_CHECKING
  { "Kein WLAN - bitte zuerst verbinden",
    "No WiFi - please connect first",
    "Pas de WiFi - connectez-vous d'abord" },  // STR_GH_OTA_NO_WIFI
  { "Bereits aktuell",
    "Already up to date",
    "Déjà à jour" },  // STR_GH_OTA_UP_TO_DATE
  { "Update verfügbar: %s",
    "Update available: %s",
    "Mise à jour disponible : %s" },  // STR_GH_OTA_UPDATE_AVAIL
  { "Jetzt installieren",
    "Install Now",
    "Installer maintenant" },  // STR_GH_OTA_UPDATE_BTN
  { "Installiere... bitte warten",
    "Installing... please wait",
    "Installation... veuillez patienter" },  // STR_GH_OTA_FLASHING
  { "Update erfolgreich - startet neu...",
    "Update successful - restarting...",
    "Mise à jour réussie - redémarrage..." },  // STR_GH_OTA_FLASH_OK
  { "Update fehlgeschlagen",
    "Update failed",
    "Échec de la mise à jour" },  // STR_GH_OTA_FLASH_FAIL
  { "Installiert: %s",
    "Installed: %s",
    "Installée : %s" },  // STR_GH_OTA_INSTALLED
  { "Aktuell: %s",
    "Latest: %s",
    "Dernière : %s" },  // STR_GH_OTA_LATEST
  { "Pre-release",
    "Pre-release",
    "Pré-version" },  // STR_GH_OTA_PRERELEASE
  { "Autom. Suche",
    "Auto check",
    "Recherche auto" },  // STR_GH_OTA_AUTOCHECK
  { "Ältere Version verfügbar: %s",
    "Older release available: %s",
    "Version plus ancienne disponible : %s" },  // STR_GH_OTA_OLDER
  { "Zurückstufen",
    "Downgrade",
    "Rétrograder" },  // STR_GH_OTA_DOWNGRADE_BTN
  { "Auf %s zurückstufen?\nDiese Version ist älter als die installierte.",
    "Downgrade to %s?\nThis release is older than the installed one.",
    "Revenir à %s ?\nCette version est plus ancienne que celle installée." },  // STR_GH_OTA_DOWNGRADE_ASK

  { "Last Used Modus",
    "Last Used Mode",
    "Mode Last Used" },  // STR_BTN_LASTUSED_MODE
  { "OpenSpoolMan oder SpoolmanScale",
    "OpenSpoolMan or SpoolmanScale",
    "OpenSpoolMan ou SpoolmanScale" },  // STR_BTN_LASTUSED_MODE_SUB
  { "Last Used Modus",
    "Last Used Mode",
    "Mode Last Used" },  // STR_LASTUSED_TITLE
  { "OpenSpoolMan",
    "OpenSpoolMan",
    "OpenSpoolMan" },  // STR_LASTUSED_OPT_OSM
  { "Zuletzt gewogen",
    "Last Weighed",
    "Dernière pesée" },  // STR_LASTUSED_OPT_WEIGHED
  { "Wird die Nutzung deines Filaments in Spoolman genau getrackt, z.B. automatisch durch OpenSpoolMan beim Bambu Lab Drucker, dann wird auf dem Hauptscreen das Datum der letzten Benutzung aus Spoolman angezeigt.",
    "If your filament usage is tracked in Spoolman, e.g. automatically via OpenSpoolMan with a Bambu Lab printer, the main screen will show the date of the last use from Spoolman.",
    "Si la consommation de votre filament est suivie avec précision dans Spoolman, par exemple automatiquement par OpenSpoolMan avec une imprimante Bambu Lab, l'écran principal affiche la date de dernière utilisation enregistrée dans Spoolman." },  // STR_LASTUSED_DESC_OSM
  { "Wird das 'Last Used' Feld in Spoolman nicht aktiv von dir genutzt, dann benutzt SpoolmanScale dieses Feld, um das Datum des letzten Gewichtsupdates zu speichern. Der Hauptscreen zeigt dann 'Zuletzt gewogen' statt 'Zuletzt benutzt'.",
    "If you don't actively use the 'Last Used' field in Spoolman, SpoolmanScale will use it to store the date of the last weight update. The main screen will then show 'Last Weighed' instead of 'Last Used'.",
    "Si vous ne vous servez pas du champ 'Last Used' (Dernière utilisation) de Spoolman, SpoolmanScale y inscrit la date de la dernière mise à jour du poids. L'écran principal affiche alors 'Dernière pesée' au lieu de 'Dernier usage'." },  // STR_LASTUSED_DESC_WEIGHED
  // FilaMan keeps both values itself, so the wording differs from Spoolman:
  // nothing is written, the scale only picks which source it reads.
  { "FilaMan",
    "FilaMan",
    "FilaMan" },  // STR_LASTUSED_OPT_FILAMAN
  { "FilaMan pflegt 'Zuletzt benutzt' selbst und trägt dort echten Druckverbrauch ein, z.B. über seine Druckeranbindung. Solange noch kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "FilaMan maintains 'Last Used' itself and records real print consumption there, e.g. through its printer integration. Until a print has been recorded, the main screen falls back to the last weighing.",
    "FilaMan renseigne lui-même la date de dernière utilisation d'après la consommation réelle des impressions, par exemple via sa connexion à l'imprimante. Tant qu'aucune impression n'est enregistrée, l'écran principal affiche à la place la dernière pesée." },  // STR_LASTUSED_DESC_FILAMAN_USED
  { "FilaMan protokolliert jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen' und damit, wann du die Spule zuletzt in der Hand hattest. Es wird nichts zusätzlich gespeichert.",
    "FilaMan logs every weighing with a timestamp, including the ones from this scale. The main screen then shows 'Last Weighed', i.e. when you last handled the spool. Nothing extra is stored.",
    "FilaMan enregistre la date de chaque pesée, y compris celles faites avec cette balance. L'écran principal affiche alors 'Dernière pesée', c'est-à-dire la dernière fois que vous avez eu la bobine en main. La balance n'écrit rien de plus." },  // STR_LASTUSED_DESC_FILAMAN_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing",
    "Consommation ou pesée" },  // STR_BTN_LASTUSED_MODE_SUB_FM
  // BamBuddy keeps both dates itself: last_used is stamped when a print
  // consumes the spool, last_weighed_at when a weight is written. Neither is
  // ours to fill, so unlike Spoolman nothing is repurposed here.
  { "BamBuddy",
    "BamBuddy",
    "BamBuddy" },  // STR_LASTUSED_OPT_BAMBUDDY
  { "BamBuddy trägt 'Zuletzt benutzt' selbst ein, wenn ein Druck von dieser Spule verbraucht. Solange kein Druck erfasst wurde, zeigt der Hauptscreen ersatzweise die letzte Wägung an.",
    "BamBuddy fills 'last used' itself when a print consumes this spool. Until a print has been recorded, the main screen falls back to the last weighing.",
    "BamBuddy renseigne lui-même la date de dernier usage quand une impression consomme du filament de cette bobine. Tant qu'aucune impression n'a été enregistrée, l'écran principal affiche la dernière pesée à la place." },  // STR_LASTUSED_DESC_BAMBUDDY_USED
  { "BamBuddy stempelt jede Wägung mit Zeitstempel, auch die von dieser Waage. Der Hauptscreen zeigt dann 'Zuletzt gewogen'. Nur das BamBuddy-Inventar führt dieses Feld - mit einem Spoolman-Server dahinter bleibt es leer.",
    "BamBuddy stamps every weighing, including the ones from this scale. The main screen then shows 'last weighed'. Only the BamBuddy inventory keeps this field - with a Spoolman server behind it, it stays empty.",
    "BamBuddy enregistre la date de chaque pesée, y compris celles faites avec cette balance. L'écran principal affiche alors 'Dernière pesée'. Seul l'inventaire propre à BamBuddy conserve cette date : si BamBuddy s'appuie sur un serveur Spoolman, elle reste vide." },  // STR_LASTUSED_DESC_BAMBUDDY_WEIGHED
  { "Druckverbrauch oder Wägung",
    "Print usage or weighing",
    "Consommation ou pesée" },  // STR_BTN_LASTUSED_MODE_SUB_BB
  // BamBuddy's own inventory stores consumption and derives the rest, so it
  // cannot hold more filament than the label promises. Asked before writing
  // rather than letting the value snap back on the next scan.
  { "Mehr als das Etikett",
    "More than the label",
    "Dépasse l'étiquette" },  // STR_BB_CAP_TITLE
  { "Gemessen: %.0f g. Das Etikett sagt %.0f g. BamBuddy kann nicht mehr speichern, als das Etikett hergibt - der Rest stünde danach wieder auf voll.",
    "Measured: %.0f g. The label says %.0f g. BamBuddy cannot store more than the label allows, so the remainder would read as full again.",
    "Mesuré : %.0f g. L'étiquette indique %.0f g. BamBuddy ne peut pas enregistrer plus que l'étiquette : le poids restant serait ramené à celui d'une bobine pleine." },  // STR_BB_CAP_BODY
  { "Etikett auf %.0f g anheben",
    "Raise label to %.0f g",
    "Porter l'étiquette à %.0f g" },  // STR_BB_CAP_RAISE
  { "Etikett behalten",
    "Keep the label",
    "Garder l'étiquette" },  // STR_BB_CAP_KEEP
  { "Trocknungsdatum",
    "Drying date",
    "Date de séchage" },  // STR_BB_DRIED_TITLE
  { "Nicht speichern",
    "Do not store",
    "Ne pas mémoriser" },  // STR_BB_DRIED_OFF
  { "Das Datum bleibt leer",
    "The date stays empty",
    "La date reste vide" },  // STR_BB_DRIED_OFF_SUB
  { "Spoolman hinter BamBuddy",
    "Spoolman behind BamBuddy",
    "Spoolman derrière BamBuddy" },  // STR_BB_DRIED_SPOOLMAN
  { "In extra.last_dried auf dem Spoolman-Server",
    "Into extra.last_dried on the Spoolman server",
    "Dans extra.last_dried sur le serveur Spoolman" },  // STR_BB_DRIED_SPOOLMAN_SUB
  { "Nur wenn BamBuddy auf einen Spoolman-Server zeigt",
    "Only when BamBuddy points at a Spoolman server",
    "Si BamBuddy pointe vers un serveur Spoolman" },  // STR_BB_DRIED_SPOOLMAN_NA
  { "Ins Notizfeld",
    "Into the note field",
    "Dans le champ note" },  // STR_BB_DRIED_NOTE
  { "Als [last_dried:JJJJ-MM-TT] in der Notiz",
    "As [last_dried:YYYY-MM-DD] in the note",
    "[last_dried:AAAA-MM-JJ] dans la note" },  // STR_BB_DRIED_NOTE_SUB
  { "BamBuddy hat kein Feld für ein Trocknungsdatum. Das Notizfeld geht immer und behält den übrigen Text. Der andere Weg schreibt in last_dried auf dem Spoolman-Server hinter BamBuddy.",
    "BamBuddy has no field for a drying date. The note field always works and keeps the rest of the text. The other route writes into last_dried on the Spoolman server behind BamBuddy.",
    "BamBuddy n'a aucun champ pour la date de séchage. Le champ note fonctionne dans tous les cas et garde le reste du texte. L'option 'Spoolman derrière BamBuddy' écrit dans last_dried, sur le serveur Spoolman relié à BamBuddy." },  // STR_BB_DRIED_INFO
  // Short forms for the connection test line, which has room for about 34
  // characters. The "Inventar:" prefix is what says this names the data
  // source and not the backend - bare "Spoolman" always means the native one.
  { "Inventar: BamBuddy",
    "Inventory: BamBuddy",
    "Inventaire : BamBuddy" },  // STR_BB_INV_OWN
  { "Inventar: Spoolman",
    "Inventory: Spoolman",
    "Inventaire : Spoolman" },  // STR_BB_INV_SPOOLMAN
  // Label above the database name on the backend screen. Same word as the
  // short form above, so the two places do not invent two vocabularies.
  { "Inventar",
    "Inventory",
    "Inventaire" },  // STR_BACKEND_INVENTORY

  // AMS view. The unit names are built here rather than taken from the
  // server: both backends generate their own "AMS A" style labels, and a
  // generated English label would land on the screen untranslated.
  { "AMS-Status",
    "AMS status",
    "État de l'AMS" },  // STR_AMSV_TITLE
  { "AMS ansehen",
    "Show the AMS",
    "Voir l'AMS" },  // STR_AMSV_BTN
  { "Fächer des Druckers",
    "The printer's bays",
    "Les bacs de l'imprimante" },  // STR_AMSV_BTN_SUB
  { "Neu laden",
    "Reload",
    "Recharger" },  // STR_AMSV_RELOAD
  { "AMS wird gelesen...",
    "Reading the AMS...",
    "Lecture de l'AMS..." },  // STR_AMSV_LOADING
  { "AMS %d",
    "AMS %d",
    "AMS %d" },  // STR_AMSV_UNIT
  { "AMS HT %d",
    "AMS HT %d",
    "AMS HT %d" },  // STR_AMSV_UNIT_HT
  { "Extern",
    "External",
    "Externe" },  // STR_AMSV_UNIT_EXT
  { "Leer",
    "Empty",
    "Vide" },  // STR_AMSV_EMPTY
  { "%d%%",
    "%d%%",
    "%d%%" },  // STR_AMSV_HUM_PCT
  { "Stufe %d",
    "Step %d",
    "Niveau %d" },  // STR_AMSV_HUM_LEVEL
  // Says why the bays are still there. FilaMan keeps the assignment in its
  // database but temperature and humidity are live MQTT readings, so an
  // unreachable printer shows full bays with no climate - which looks like a
  // fault in the scale unless the line explains it.
  { "offline, letzter Stand",
    "offline, last known state",
    "hors ligne, dernier état" },  // STR_AMSV_OFFLINE
  // Not the same as offline: the server has simply never heard from its
  // driver. Saying "offline" there blames the printer for the server.
  { "Status unbekannt",
    "state unknown",
    "état inconnu" },  // STR_AMSV_UNKNOWN
  { "Kein AMS gemeldet",
    "No AMS reported",
    "Aucun AMS signalé" },  // STR_AMSV_NO_AMS
  { "Kein Drucker gefunden",
    "No printer found",
    "Aucune imprimante trouvée" },  // STR_AMSV_NO_PRINTER
  { "Server antwortet %d",
    "The server answers %d",
    "Le serveur répond %d" },  // STR_AMSV_ERR_HTTP
  { "Kein Netz",
    "No network",
    "Pas de réseau" },  // STR_AMSV_ERR_NET
  { "Zu wenig Speicher für alle Fächer",
    "Not enough memory for every bay",
    "Mémoire insuffisante pour tous les bacs" },  // STR_AMSV_ERR_FULL
  { "Trocknet %d °C, %d min",
    "Drying %d °C, %d min",
    "Séchage %d °C, %d min" },  // STR_AMSV_DRYING_TIME
  { "Trocknet %d °C",
    "Drying %d °C",
    "Séchage %d °C" },  // STR_AMSV_DRYING_TEMP
  { "druckt %d%%",
    "printing %d%%",
    "imprime %d%%" },  // STR_AMSV_JOB
  // The printer's own states, in words. Bambu keeps the last job and its
  // 100 % on the wire after a print until the next one starts, so the
  // percentage alone would read "printing 100%" for days.
  { "pausiert bei %d%%",
    "paused at %d%%",
    "en pause à %d%%" },  // STR_AMSV_JOB_PAUSED
  { "Druck fertig",
    "print finished",
    "impression terminée" },  // STR_AMSV_STATE_FINISH
  { "Druck abgebrochen",
    "print failed",
    "impression échouée" },  // STR_AMSV_STATE_FAILED
  { "bereit",
    "idle",
    "prête" },  // STR_AMSV_STATE_IDLE
  { "bereitet vor",
    "preparing",
    "en préparation" },  // STR_AMSV_STATE_PREPARE
  // Which of several printers is on screen. Same in both languages, but
  // it goes through T() so a language that numbers differently can change it.
  { "%d/%d",
    "%d/%d",
    "%d/%d" },  // STR_AMSV_PRN_OF
  { "%s -> in welches Fach?",
    "%s -> into which bay?",
    "%s -> dans quel bac ?" },  // STR_AMSV_PICK_HEAD
  { "Spule ist zugeordnet",
    "The spool is assigned",
    "La bobine est affectée" },  // STR_AMSV_ASSIGNED
  { "Spule umgezogen",
    "The spool moved",
    "La bobine a changé de bac" },  // STR_AMSV_MOVED
  { "Zuordnung fehlgeschlagen",
    "Assignment failed",
    "Échec de l'affectation" },  // STR_AMSV_ASSIGN_FAIL
  { "Nach dem Wiegen ins AMS",
    "Into the AMS after weighing",
    "Vers l'AMS après la pesée" },  // STR_BBAMS_ASK
  { "Beim Abheben nach dem Fach fragen",
    "Ask for the bay on removal",
    "Demander le bac au retrait" },  // STR_BBAMS_ASK_SUB
  { "An: nach dem Wiegen einer bekannten Spule fragt die Waage beim Abheben, in welches AMS-Fach sie geht, und trägt das in BamBuddy ein.\n\nBamBuddy konfiguriert das Fach dabei über MQTT am Drucker mit - Material, Farbe und Temperaturen. Das ist gewollt, aber es wirkt auf den Drucker, nicht nur auf die Datenbank.",
    "On: after a known spool has been weighed, the scale asks on removal which AMS bay it goes into and records that in BamBuddy.\n\nBamBuddy also configures the bay on the printer over MQTT while doing so - material, colour and temperatures. That is intended, but it acts on the printer, not only on the database.",
    "Activé : quand vous retirez une bobine connue après sa pesée, la balance demande dans quel bac AMS vous la placez, puis l'enregistre dans BamBuddy.\n\nBamBuddy configure alors aussi ce bac sur l'imprimante par MQTT : matériau, couleur et températures. C'est voulu, mais cela agit sur l'imprimante, pas seulement sur la base de données." },  // STR_BBAMS_ASK_INFO
  { "Werkseinstellungen",         "Factory Reset",      "Réinitialisation" },  // STR_BTN_FACTORY_RESET
  { "Alle Einstellungen löschen", "Erase all settings", "Effacer tous les réglages" },  // STR_BTN_FACTORY_RESET_SUB
  { "Werkseinstellungen?",        "Factory Reset?",     "Réinitialiser ?" },  // STR_FACTORY_RESET_TITLE
  { "Alle Einstellungen werden gelöscht:\nWLAN, Server-Adresse, Kalibrierung,\nSprache und alle anderen Daten.\nDanach startet das Gerät neu.",
    "All settings will be erased:\nWiFi, server address, calibration,\nlanguage and all other data.\nThe device will restart afterwards.",
    "Tous les réglages seront effacés :\nWiFi, adresse du serveur, étalonnage,\nlangue et toutes les autres données.\nL'appareil redémarre ensuite." },  // STR_FACTORY_RESET_MSG
  { "Ja, alles löschen", "Yes, erase everything",
    "Oui, tout effacer" },  // STR_FACTORY_RESET_CONFIRM
  { "Spule kopieren", "Copy spool",
    "Copier la bobine" },  // STR_BTN_COPY_SPOOL
  { "Spule kopieren", "Copy spool",
    "Copier la bobine" },  // STR_COPY_TITLE
  { "Spoolman-ID eingeben", "Enter Spoolman ID",
    "Saisir l'ID Spoolman" },  // STR_COPY_ID_BTN
  { "Aktive Spulen", "Active spools",
    "Bobines actives" },  // STR_COPY_ACTIVE_BTN
  { "Archivierte Spulen", "Archived spools",
    "Bobines archivées" },  // STR_COPY_ARCHIVED_BTN
  { "Neue Spule anlegen?", "Create new spool?",
    "Créer une bobine ?" },  // STR_COPY_CONFIRM_TITLE
  { "Vorlage: %s\nZuletzt bekannt: %.0f g\nWaagengewicht (netto): %.0f g\n-> wird übernommen", "Template: %s\nLast known: %.0f g\nNew spool weight (net): %.0f g\n-> will be saved",
    "Modèle : %s\nDernier poids connu : %.0f g\nPoids sur la balance (net) : %.0f g\n-> sera enregistré" },  // STR_COPY_CONFIRM_MSG
  { "Spule erstellt!", "Spool created!",
    "Bobine créée !" },  // STR_COPY_OK
  { "Fehler beim Erstellen", "Error creating spool",
    "Échec de la création" },  // STR_COPY_FAIL
  { "Keine Spulen gefunden", "No spools found",
    "Aucune bobine trouvée" },  // STR_COPY_NO_SPOOLS
  { "Setup überspringen", "Skip setup",
    "Passer la config." },  // STR_BTN_SKIP_SETUP
  { "Unlink", "Unlink",
    "Dissocier" },  // STR_UNLINK_BTN
  { "Spule unlinken?", "Unlink spool?",
    "Dissocier la bobine ?" },  // STR_UNLINK_TITLE
  { "Löscht den Eintrag im Tag-Feld in Spoolman.\nDie Spule bleibt erhalten.",
    "Clears the tag field entry in Spoolman.\nThe spool itself is kept.",
    "Efface l'entrée du champ tag dans Spoolman.\nLa bobine elle-même est conservée." },  // STR_UNLINK_MSG
  { "Ja, unlinken", "Yes, unlink",
    "Oui, dissocier" },  // STR_UNLINK_CONFIRM
  { "Verbinde mit WLAN...", "Connecting to WiFi...",
    "Connexion au WiFi..." },  // STR_WIFI_CONNECTING_BOOT
  { "Gerät wird gestartet...", "Starting up, please wait...",
    "Démarrage de l'appareil..." },  // STR_BOOTING
  { "Neustart", "Reboot",
    "Redémarrer" },  // STR_BTN_REBOOT
  { "Gerät neu starten", "Restart device",
    "Redémarrer l'appareil" },  // STR_BTN_REBOOT_SUB
  { "Ganze Gramm", "Whole grams",
    "Grammes entiers" },  // STR_WHOLE_GRAM
  { "Mehr Spulen gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More spools found - not listed? Use Spool-ID",
    "Liste incomplète - bobine absente ? Liez-la par son ID" },  // STR_LIST_MORE_SPOOLS
  { "Mehr Hersteller gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More vendors found - not listed? Use Spool-ID",
    "Liste incomplète - fabricant absent ? Liez par l'ID de bobine" },  // STR_LIST_MORE_VENDORS
  { "Mehr Materialien gefunden - nicht gelistet? Per Spool-ID verknüpfen", "More materials found - not listed? Use Spool-ID",
    "Liste incomplète - matériau absent ? Liez par l'ID de bobine" },  // STR_LIST_MORE_MATS

  // Auto-Weight
  { "Auto-Gewichtsupdate",
    "Auto weight update",
    "Envoi auto du poids" },  // STR_AUTO_WEIGHT_TITLE
  { "Sobald eine Spule erkannt und das Gewicht\n3 Sekunden stabil ist, wird es automatisch\ngespeichert (ohne Beutel).",
    "Once a spool is detected and the weight\nis stable for 3 seconds, it will be saved\nautomatically (without bag).",
    "Dès qu'une bobine est reconnue et que le poids\nest stable pendant 3 secondes, il est enregistré\nautomatiquement (sachet non déduit)." },  // STR_AUTO_WEIGHT_INFO
  { LV_SYMBOL_REFRESH " Auto aktivieren",
    LV_SYMBOL_REFRESH " Enable auto",
    LV_SYMBOL_REFRESH " Activer le mode auto" },  // STR_AUTO_WEIGHT_ENABLE
  { LV_SYMBOL_REFRESH " Auto deaktivieren",
    LV_SYMBOL_REFRESH " Disable auto",
    LV_SYMBOL_REFRESH " Arrêter le mode auto" },  // STR_AUTO_WEIGHT_DISABLE
  { "Lagerort",
    "Location",
    "Emplacement" },  // STR_BTN_LOCATION
  { "Lagerort wählen",
    "Select location",
    "Choisir l'emplacement" },  // STR_LOCATION_TITLE
  { LV_SYMBOL_CLOSE " Kein Lagerort",
    LV_SYMBOL_CLOSE " No location",
    LV_SYMBOL_CLOSE " Aucun emplacement" },  // STR_LOCATION_NONE
  { "Lade...",
    "Loading...",
    "Chargement..." },  // STR_LOCATION_LOADING
  { "Kein WLAN",
    "No WiFi",
    "Pas de WiFi" },  // STR_LOCATION_NO_WIFI
  { "Keine Spoolman-Lagerorte gefunden",
    "No Spoolman locations found",
    "Aucun emplacement Spoolman trouvé" },  // STR_LOCATION_NO_LOCATIONS
  { "Leere Lagerorte werden nicht angezeigt",
    "Empty locations are not shown",
    "Les emplacements vides ne sont pas affichés" },  // STR_LOCATION_HINT_EMPTY
  { "Zu viele Lagerorte - nicht alle angezeigt",
    "Too many locations - not all shown",
    "Trop d'emplacements - tous ne sont pas affichés" },  // STR_LOCATION_LIMIT_HIT
  { "Ortsabfrage bei Entnahme", "Location on removal",
    "Demander l'emplacement au retrait" },  // STR_BTN_AUTO_LOC_POPUP
  { "Trocknungserinnerung",     "Drying Reminder",     "Rappel de séchage" },  // STR_BTN_DRYING_REMINDER
  { "Trocknungserinnerung",     "Drying Reminder",     "Rappel de séchage" },  // STR_DRYING_REMINDER_TITLE

  // Drying Reminder Screen
  { "Aus",      "Off",      "Désactivé" },  // STR_DRY_MODE_OFF
  { "Material", "Material", "Matériau" },  // STR_DRY_MODE_MATERIAL
  { "Manuell",  "Manual",   "Manuel" },  // STR_DRY_MODE_MANUAL
  { "Kein Ampelsignal aktiv.\n\nMaterial: Schwellwerte pro Filamenttyp\n(konfigurierbar im Browser).\n\nManuell: Eigene Grenzwerte in Tagen.",
    "No alert signal active.\n\nMaterial: Thresholds per filament type\n(configurable in browser).\n\nManual: Custom limits in days.",
    "Aucun code couleur (vert, jaune, rouge).\n\nMatériau : seuils par type de filament\n(réglables dans le navigateur).\n\nManuel : vos propres seuils, en jours." },  // STR_DRY_OFF_DESC
  { "Schwellwerte im Browser editierbar.", "Thresholds editable in browser.",
    "Seuils modifiables dans le navigateur." },  // STR_DRY_MAT_HINT
  { "Material", "Material",
    "Matériau" },  // STR_DRY_MAT_HDR_MAT
  { "Gelb (Tage)", "Yellow (days)",
    "Jaune (jours)" },  // STR_DRY_MAT_HDR_YELLOW
  { "Rot (Tage)", "Red (days)",
    "Rouge (jours)" },  // STR_DRY_MAT_HDR_RED
  { "Gelb ab", "Yellow from",
    "Jaune dès" },  // STR_DRY_MAN_YELLOW_LBL
  { "Rot ab", "Red from",
    "Rouge dès" },  // STR_DRY_MAN_RED_LBL
  { "Tippen zum Bearbeiten", "Tap to edit",
    "Touchez pour modifier" },  // STR_DRY_MAN_EDIT_HINT
  { "Grenzwerte gelten für alle Materialien.", "Limits apply to all materials.",
    "Ces seuils s'appliquent à tous les matériaux." },  // STR_DRY_MAN_INFO
  { "Tage", "days",
    "jours" },  // STR_DRY_DAYS_UNIT
  { "Gelb-Schwellwert", "Yellow threshold",
    "Seuil jaune" },  // STR_DRY_NUMPAD_YELLOW_TITLE
  { "Rot-Schwellwert", "Red threshold",
    "Seuil rouge" },  // STR_DRY_NUMPAD_RED_TITLE
  { "Effektive Werte (%.1fx Multiplikator eingerechnet)", "Effective values (%.1fx multiplier included)",
    "Valeurs effectives (facteur sous vide %.1fx inclus)" },  // STR_DRY_MAT_EFF_NOTE
  { "Versiegelt", "Sealed",
    "Sous vide" },  // STR_DRY_SEALED_HDR

  // Backend selection. "Spoolman" and "FilaMan" are product names and stay
  // untranslated, so they are not in this table.
  // "Server" described the technology, not the purpose. Both Spoolman and
  // FilaMan manage a filament inventory, and that is what the user picks
  // here. The address screen keeps "Server", because a server address is
  // literally what gets typed in there.
  { "Filamentverwaltung", "Filament manager", "Gestion du filament" },  // STR_BACKEND_TITLE
  { "Adresse",            "Address",          "Adresse" },  // STR_BACKEND_ADDRESS
  { "API-Key",            "API key",          "Clé d'API" },  // STR_BACKEND_APIKEY
  { "Device-Token",       "Device token",     "Jeton d'appareil" },  // STR_BACKEND_DEVICE_TOKEN
  { "gesetzt",            "set",              "en mémoire" },  // STR_BACKEND_SET
  { "fehlt",              "missing",          "à définir" },  // STR_BACKEND_MISSING

  // Web interface. The same server serves the firmware upload and the
  // FilaMan credentials, so the screen title stays neutral.
  { "Weboberfläche", "Web interface", "Interface web" },  // STR_WEB_TITLE
  { "Adresse am Rechner im Browser öffnen und dort API-Key und Gerätecode eintragen. Der Status unten aktualisiert sich von selbst.",
    "Open this address in a browser on your computer and enter the API key and device code there. The status below updates on its own.",
    "Ouvrez cette adresse dans un navigateur sur votre ordinateur, et saisissez-y la clé d'API et le code d'appareil. L'état ci-dessous se met à jour tout seul." },  // STR_WEB_SETUP_HINT
  // BamBuddy has one credential where FilaMan has two, so the sentence that
  // tells the user what to type differs.
  { "Adresse am Rechner im Browser öffnen und dort den API-Key eintragen. Der Status unten aktualisiert sich von selbst.",
    "Open this address in a browser on your computer and enter the API key there. The status below updates on its own.",
    "Ouvrez cette adresse dans un navigateur sur votre ordinateur, et saisissez-y la clé d'API. L'état ci-dessous se met à jour tout seul." },  // STR_WEB_SETUP_HINT_BB
  { "Im Browser einrichten", "Set up in browser", "Config. navigateur" },  // STR_BTN_WEB_SETUP
  { "Fertig",                "Done",              "Terminer" },  // STR_BTN_FINISH
  { "Weiter",                "Next",              "Suivant" },  // STR_BTN_NEXT
  { "Welche Filamentverwaltung benutzt du? Das lässt sich später jederzeit im Menü ändern.",
    "Which filament manager do you use? This can be changed in the menu at any time.",
    "Quel gestionnaire de filament utilisez-vous ? Vous pourrez le changer à tout moment dans le menu." },  // STR_SETUP_BACKEND_HINT
  // Shown instead of a spool count when the server answered but the number
  // could not be asked for yet, which is the normal FilaMan setup case.
  { "verbunden",         "connected",       "connecté" },  // STR_CONNECTED
  { "AN",                "ON",              "ON" },  // STR_ON
  { "AUS",               "OFF",             "OFF" },  // STR_OFF
  { "Im Browser öffnen", "Open in browser", "Navigateur" },  // STR_BTN_OPEN_BROWSER
  // Names every product in both languages and in every backend mode. Not
  // passed through backendText(), see the comment at the call site.
  { "Nicht mit Spoolman, FilaMan oder BamBuddy verbunden",
    "Not affiliated with Spoolman, FilaMan or BamBuddy",
    "Sans lien avec Spoolman, FilaMan ou BamBuddy" },  // STR_NOT_AFFILIATED
  { "Kein Tag erkannt, bitte neu auflegen",
    "No tag detected, place it again",
    "Aucun tag détecté, reposez-le" },  // STR_LINK_NO_TAG

  // Main screen weight box and More-info detail grid
  { "Waage - Spule",     "Scale - Spool",        "Balance - Bobine" },  // STR_LBL_SCALE_SPOOL_CAP
  { "Gesamt",            "Total",                "Total" },  // STR_LBL_TOTAL_CAP
  { "o. Beutel",         "w/o bag",              "s. sachet" },  // STR_LBL_WO_BAG_CAP
  { "Farbe",             "Hex Color",            "Couleur" },  // STR_LBL_HEX_COLOR
  { "Produktionsdatum",  "Production date",      "Date de production" },  // STR_LBL_PRODUCTION_DATE
  { "Artikelnr.",        "Article no.",          "Réf. article" },  // STR_LBL_ARTICLE_NO_SHORT
  { "Leergewicht Spule", "Spool weight (empty)", "Poids bobine vide" },  // STR_LBL_SPOOL_WEIGHT_EMPTY

  // Status bar address selector
  { "Im Statusbalken zeigen", "Show in status bar", "Afficher dans la barre d'état" },  // STR_BTN_IP_STATUSBAR
  { "Gerät",                  "Device",             "Appareil" },  // STR_IP_BAR_DEVICE

  // Remote link. Deliberately not passed through backendText(): this only
  // ever happens in FilaMan mode, so naming it outright is clearer than a
  // substitution that can never differ.
  { "FilaMan: Spule verknüpfen?", "FilaMan: link spool?", "FilaMan : lier la bobine ?" },  // STR_REMOTE_LINK_TITLE
  { "Aufliegenden Tag mit dieser Spule verknüpfen?",
    "Link the tag on the scale to this spool?",
    "Lier le tag posé sur la balance à cette bobine ?" },  // STR_REMOTE_LINK_QUESTION
  { "Verknüpfen",             "Link",                   "Lier" },  // STR_REMOTE_LINK_CONFIRM
  { "Details nicht abrufbar", "Details unavailable",    "Détails indisponibles" },  // STR_REMOTE_LINK_NO_DETAILS
  { "Verknüpfung abgelaufen", "Link request timed out", "Demande de liaison expirée" },  // STR_REMOTE_LINK_TIMEOUT

  // Tag versus spool comparison
  { "Tag",      "Tag",      "Tag" },  // STR_REMOTE_LINK_COL_TAG
  { "Spule",    "Spool",    "Bobine" },  // STR_REMOTE_LINK_COL_SPOOL
  { "Material", "Material", "Matériau" },  // STR_REMOTE_LINK_ROW_MATERIAL
  { "Farbe",    "Colour",   "Couleur" },  // STR_REMOTE_LINK_ROW_COLOR

  // FilaMan options sub screen
  { "Weitere Optionen",        "More options",       "Autres options" },  // STR_BTN_MORE_OPTIONS
  { "Mehrere Tags verknüpfen", "Link multiple tags", "Lier plusieurs tags" },  // STR_CU_WRITE
  { "Schreibt in Spoolmans Feld card_uids",
    "Writes to Spoolman's card_uids field",
    "Écrit dans le champ card_uids de Spoolman" },  // STR_CU_WRITE_SUB
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
    "Activé : un UID scanné s'ajoute à la liste au lieu de la remplacer. Les bobines déjà liées restent proposées au moment de lier, pour pouvoir leur ajouter un second tag.\n\nDésactivé : card_uids contient toujours un seul UID.\n\nCe réglage ne concerne que card_uids, seul champ supplémentaire qui accepte une liste. Spoolman NFC gère plusieurs tags de lui-même et n'en a pas besoin." },  // STR_CU_WRITE_INFO
  { "UID nicht hinzugefügt",        "UID not added",            "UID non ajouté" },  // STR_CU_NOT_WRITTEN
  { "Tag hängt schon an Spule #%d", "Tag already on spool #%d",
    "Ce tag est déjà sur la bobine #%d" },  // STR_TAG_ON_OTHER_SPOOL
  { LV_SYMBOL_WARNING "  Spule hat schon UIDs",
    LV_SYMBOL_WARNING "  Spool already has UIDs",
    LV_SYMBOL_WARNING "  La bobine a déjà des UID" },  // STR_WARN_A_ADD_TITLE
  { "Spule #%d  |  %s %s\nHat bereits %d UID(s)",
    "Spool #%d  |  %s %s\nAlready has %d UID(s)",
    "Bobine #%d  |  %s %s\nPorte déjà %d UID" },  // STR_WARN_A_ADD_INFO
  { "Spule #%d\nHat bereits %d UID(s)",
    "Spool #%d\nAlready has %d UID(s)",
    "Bobine #%d\nPorte déjà %d UID" },  // STR_WARN_A_ADD_SHORT
  { "UID hinzufügen", "Add UID", "Ajouter l'UID" },  // STR_BTN_ADD_UID
  { "Diese Spule ist mehrfach gebunden.\nNur das Tag auf der Waage lösen\noder die ganze Bindung?",
    "This spool is bound more than once.\nRemove only the tag on the scale\nor the whole binding?",
    "Cette bobine est liée plusieurs fois.\nDissocier le tag sur la balance\nou toute la liaison ?" },  // STR_UNLINK_MULTI_MSG
  { "Nur dieses Tag",                "Only this tag",                "Ce tag seulement" },  // STR_BTN_UNLINK_ONE
  { "Alle lösen",                    "Unlink all",                   "Tout dissocier" },  // STR_BTN_UNLINK_ALL
  { "Ohne Nachfrage verknüpfen",     "Link without asking",          "Lier sans demander" },  // STR_FLM_AUTOLINK
  { "wenn die Spule schon aufliegt", "when the spool is already on",
    "si la bobine est déjà posée" },  // STR_FLM_AUTOLINK_SUB
  { " (Filament)",                   " (filament)",                  " (filament)" },  // STR_TARE_FROM_FILAMENT
  { " (Hersteller)",                 " (brand)",                     " (fabricant)" },  // STR_TARE_FROM_BRAND
  { "Ohne Beutel wiegen - sonst %.0f g zu viel",
    "Weigh without the bag - %.0f g too much otherwise",
    "Pesez sans le sachet - sinon %.0f g de trop" },  // STR_SPOOL_WEIGHT_BAG_HINT
  { "Ohne Tag wiegen",              "Weigh without a tag",           "Peser sans tag" },  // STR_FLM_TAGLESS
  { "wenn kein Tag aufgelegt wird", "when no tag is presented",
    "si aucun tag n'est présenté" },  // STR_FLM_TAGLESS_SUB
  { "Spule gewählt - jetzt wiegen", "Spool selected - weigh it now",
    "Bobine choisie - pesez-la" },  // STR_REMOTE_LINK_WEIGH
  { LV_SYMBOL_EYE_CLOSE "  Bildschirm aus nach (Min.)",
    LV_SYMBOL_EYE_CLOSE "  Screen off after (min.)",
    LV_SYMBOL_EYE_CLOSE "  Écran éteint après (min)" },  // STR_SCREENOFF_LABEL
  { "Nie", "Never", "Jamais" },  // STR_SCREENOFF_NEVER
  { "Löst FilaMan eine Verknüpfung aus und die Spule liegt schon auf der Waage, wird ohne Rückfrage verknüpft. Passen Material oder Farbe nicht zusammen, fragt die Waage trotzdem nach.",
    "When FilaMan triggers a link and the spool is already on the scale, it is linked without asking. If the material or colour do not match, the scale asks anyway.",
    "Quand une liaison est lancée depuis FilaMan alors que la bobine est déjà sur la balance, la liaison se fait sans confirmation. Si le matériau ou la couleur du tag ne correspondent pas à la bobine choisie, la balance demande quand même." },  // STR_FLM_AUTOLINK_INFO
  { "Wird nach einer Verknüpfung aus FilaMan innerhalb von 10 Sekunden kein Tag aufgelegt, lädt die Waage die dort gewählte Spule trotzdem und zeigt sie an. Gewogen wird sie danach wie jede andere: bei eingeschalteter Automatik von selbst, sonst über den Gewichtsknopf. FilaMans eigener Dialog meldet dabei einen Fehler, weil dort kein Tag geschrieben wurde - geladen ist die Spule trotzdem. Auf einen Tag wird nie etwas geschrieben, und die Zuordnung endet, sobald die Spule wieder heruntergenommen wird.",
    "If no tag is presented within 10 seconds of a link from FilaMan, the scale loads the spool chosen there anyway and shows it. Weighing then works as for any other spool: on its own when automatic weighing is on, otherwise through the weight button. FilaMan's own dialog reports an error because no tag was written there - the spool is loaded regardless. Nothing is ever written to a tag, and the spool is released as soon as it is taken off the pad.",
    "Si aucun tag n'est posé dans les 10 secondes qui suivent une liaison lancée depuis FilaMan, la balance charge quand même la bobine choisie dans FilaMan et l'affiche. La pesée se fait ensuite comme pour toute autre bobine : toute seule si la pesée automatique est activée, sinon avec le bouton Envoyer le poids. FilaMan affiche de son côté une erreur, puisqu'aucun tag n'a été écrit, mais la bobine est bien chargée. Rien n'est jamais écrit sur un tag, et cette association temporaire prend fin dès que la bobine est retirée de la balance." },  // STR_FLM_TAGLESS_INFO
  // FilaMan variants of the spool-weight scope buttons. The Spoolman ones
  // carry the REST field name in brackets, which is a real reading aid there
  // because the three scopes use three different names. In FilaMan two of
  // the three are called the same thing, so the bracket helps nobody and is
  // simply wrong on top. FilaMan also calls a vendor a manufacturer.
  { "Diese Spule",     "This spool",    "Cette bobine" },  // STR_BTN_THIS_SPOOL_FM
  { "Dieses Filament", "This filament", "Ce filament" },  // STR_BTN_THIS_FILAMENT_FM
  { "Hersteller",      "Manufacturer",  "Fabricant" },  // STR_BTN_THIS_VENDOR_FM
  { LV_SYMBOL_CLOSE " leer / Archivieren\nRest wird 0",
    LV_SYMBOL_CLOSE " empty / Archive\nremaining set to 0",
    LV_SYMBOL_CLOSE " vide / Archiver\nreste mis à 0" },  // STR_BTN_ARCHIVE_EMPTY_FM

  // Auto AMS assignment. FilaMan marks a freshly weighed spool as pending on
  // every printer driver for a few seconds, so the next tray to be loaded
  // gets it. The wording avoids "auto assign" on its own because the whole
  // point of the ask mode is that it is not automatic.
  { "Auto AMS-Zuordnung",           "Auto AMS assign",                "Affectation AMS auto" },  // STR_AMS_TITLE
  { "Spule beim Einlegen zuordnen", "assign the spool as it goes in",
    "affecter la bobine à l'insertion" },  // STR_AMS_SUB
  { "FilaMan merkt eine gewogene Spule einige Sekunden vor. Wer in dieser Zeit ein AMS-Fach belädt, bekommt sie zugeordnet. Geöffnet wird das Fenster nur von einem Gewicht, deshalb bucht die Waage beim Zuordnen ein zweites Mal: die Messung steht dann doppelt im Protokoll, der Wert bleibt gleich. Wandert die Spule ohnehin gleich in den Drucker, genügt kurz auflegen.",
    "FilaMan reserves a weighed spool for a few seconds. Whoever loads an AMS tray in that time gets it assigned. Only a weight opens that window, so assigning books the value a second time: the measurement then shows twice in the log, the value stays the same. If the spool is going into the printer anyway, just resting it on the pad is enough.",
    "FilaMan réserve une bobine pesée pendant quelques secondes : si un bac AMS est chargé pendant cette fenêtre, la bobine lui est affectée. Seul un envoi de poids ouvre la fenêtre : pour affecter la bobine, la balance renvoie donc son poids, qui figure alors deux fois dans l'historique FilaMan, avec la même valeur. Si la bobine va de toute façon tout de suite dans l'imprimante, il suffit de la poser un instant sur la balance." },  // STR_AMS_INFO
  { "Aus",        "Off", "Désactivé" },  // STR_AMS_MODE_OFF
  { "Nachfragen", "Ask", "Demander" },  // STR_AMS_MODE_ASK
  // Not "Immer an": next to "Nachfragen" that reads as "the question is
  // always on", which is the opposite of what it does. Users asking for a way
  // out of the popup had the mode in front of them and did not recognise it.
  { "Automatisch", "Automatic", "Automatique" },  // STR_AMS_MODE_ALWAYS
  { "Es wird nichts vorgemerkt. Wiegen und Lagerort verhalten sich genau wie bisher.",
    "Nothing is reserved. Weighing and location behave exactly as before.",
    "Rien n'est réservé. La pesée et le choix de l'emplacement restent inchangés." },  // STR_AMS_OFF_DESC
  { "Beim Abnehmen wird gefragt, ob die Spule in den Drucker wandert. Ein Ja sendet das Gewicht und öffnet das Fenster.",
    "When the spool is lifted you are asked whether it goes into the printer. A yes sends the weight and opens the window.",
    "Au retrait, la balance demande si la bobine va dans l'imprimante. Un oui envoie le poids et ouvre la fenêtre d'affectation." },  // STR_AMS_ASK_DESC
  // The gain first, the price second: this is the mode people come looking
  // for when the popup is in their way, so it has to say so before it warns.
  { "Kein Popup, kein Countdown: jede Wiegung merkt die Spule vor. Der Preis ist, dass auch kurzes Nachwiegen sie vormerkt.",
    "No popup, no countdown: every weighing reserves the spool. The price is that checking a weight reserves it too.",
    "Ni question ni compte à rebours : chaque pesée réserve la bobine. Contrepartie : une pesée de contrôle la réserve aussi." },  // STR_AMS_ALWAYS_DESC
  { "Fenster",                               "Window",                            "Fenêtre" },  // STR_AMS_WINDOW_LBL
  { "wie lange die Spule vorgemerkt bleibt", "how long the spool stays reserved",
    "durée de réservation de la bobine" },  // STR_AMS_WINDOW_HINT
  { "s",                                     "s",                                 "s" },  // STR_AMS_SEC_UNIT
  { "Bei Ablauf", "When it runs out",
    "À l'expiration" },  // STR_AMS_TIMER_LBL
  { "wenn niemand antwortet", "when nobody answers",
    "si personne ne répond" },  // STR_AMS_TIMER_HINT
  { "Ja",                                    "Yes",                               "Oui" },  // STR_AMS_TIMER_YES
  { "Nein",                                  "No",                                "Non" },  // STR_AMS_TIMER_NO
  { "Spule jetzt ins AMS legen?", "Putting the spool into the AMS?",
    "Mettre la bobine dans l'AMS ?" },  // STR_AMS_POPUP_Q
  { "Zuordnung startet in %d s", "Assignment starts in %d s",
    "Affectation dans %d s" },  // STR_AMS_POPUP_STARTS_IN
  { "Ohne Zuordnung in %d s", "Without assigning in %d s",
    "Sans affectation dans %d s" },  // STR_AMS_POPUP_CLOSES_IN
  { "Ja, zuordnen", "Yes, assign",
    "Oui, affecter" },  // STR_AMS_BTN_YES
  { "Der ApiKey darf keine Geräte verwalten",
    "This ApiKey may not manage devices",
    "Cette clé d'API ne peut pas gérer les appareils" },  // STR_AMS_ERR_FORBIDDEN
  { "Server antwortet nicht (HTTP %d)", "Server not answering (HTTP %d)",
    "Le serveur ne répond pas (HTTP %d)" },  // STR_AMS_ERR_HTTP
  { "%.0f g sind gespeichert", "%.0f g are saved",
    "%.0f g sont enregistrés" },  // STR_AMS_POPUP_SAVED
  { "Zuordnung %d s", "Assigning %d s",
    "Affectation %d s" },  // STR_AMS_WINDOW_RUNNING
  { "Server: Zuordnung aktiv", "Server: assigning active",
    "Serveur : affectation active" },  // STR_AMS_SRV_ON
  { "Server: aus", "Server: off",
    "Serveur : désactivé" },  // STR_AMS_SRV_OFF
  { "%.0f g werden dabei gespeichert", "%.0f g will be saved too",
    "%.0f g seront enregistrés au passage" },  // STR_AMS_POPUP_WILL_SAVE
  { "Neu aus Tag anlegen", "Create from tag",
    "Créer depuis le tag" },  // STR_NEWTAG_BTN
  { "Spule aus Tag anlegen?", "Create spool from tag?",
    "Créer la bobine depuis le tag ?" },  // STR_NEWTAG_TITLE
  { "%s %s\nFarbe: %s\nWaagengewicht (netto): %.0f g", "%s %s\nColour: %s\nScale weight (net): %.0f g",
    "%s %s\nCouleur : %s\nPoids sur la balance (net) : %.0f g" },  // STR_NEWTAG_MSG
  { "Nenngewicht", "Label weight",
    "Poids nominal" },  // STR_NEWTAG_LABEL_W
  { "Spule angelegt!", "Spool created!",
    "Bobine créée !" },  // STR_NEWTAG_OK
  { "Anlegen fehlgeschlagen", "Could not create spool",
    "Création impossible" },  // STR_NEWTAG_FAIL

  { "Tag-Feld", "Tag field", "Champ du tag" },  // STR_TAG_FIELD
  { "Jedes Projekt legt die Tag-UID in ein anderes Extra-Feld, weil Spoolman "
    "lange keines dafür hatte. Das ändert sich gerade: Spoolman bekommt ein "
    "eigenes Tag-Modell.\n\n"
    "Hier wird bestimmt, wohin die Waage schreibt. Kann der Server das native "
    "Modell, wählt sie es beim ersten Scan von selbst - eine Auswahl, die du "
    "selbst getroffen hast, bleibt stehen.\n\n"
    "Gelesen wird immer aus allen Quellen, damit beim Umstellen keine Spule "
    "unsichtbar wird. Beim nächsten Verknüpfen wandert eine anderswo gefundene "
    "UID in die gewählte Quelle.\n\n"
    "Ein Extra-Feld muss dafür auf dem Server existieren - sonst lehnt Spoolman "
    "jedes Schreiben mit HTTP 400 ab und die schnelle Suche fällt auf das Laden "
    "des ganzen Inventars zurück. Für Spoolman NFC gilt das nicht, dort ist "
    "kein Feld anzulegen.",
    "Every project puts the tag UID in a different extra field, because "
    "Spoolman had none for it for a long time. That is changing: Spoolman has "
    "grown a tag model of its own.\n\n"
    "This is where you say what the scale writes to. On a server that has the "
    "native model it picks that by itself on the first scan; a choice you made "
    "yourself is left alone.\n\n"
    "Every source is always read, so nothing goes missing when you switch. On "
    "the next link a UID found elsewhere moves into the selected source.\n\n"
    "An extra field has to exist on the server for that - otherwise Spoolman "
    "rejects every write with HTTP 400 and the fast search falls back to "
    "loading the whole inventory. Spoolman NFC is exempt: there is no field to "
    "create.",
    "Chaque logiciel range l'identifiant (UID) du tag dans son propre champ supplémentaire, car Spoolman n'en a longtemps proposé aucun. Cela change : Spoolman se dote de sa propre gestion des tags.\n\nCe réglage indique où la balance écrit. Si le serveur gère les tags nativement, elle choisit cette gestion d'elle-même au premier tag lu, sauf si vous avez déjà fait votre choix.\n\nToutes les sources sont toujours lues, pour qu'aucune bobine ne devienne introuvable si vous changez de source. Quand vous liez à nouveau une bobine, son UID trouvé ailleurs passe dans la source choisie.\n\nLe champ supplémentaire doit exister sur le serveur - sinon Spoolman refuse toute écriture (erreur HTTP 400), et la balance charge tout l'inventaire au lieu d'une recherche rapide. Spoolman NFC n'est pas concerné : aucun champ à créer." },  // STR_TAG_FIELD_INFO

  { "Spoolman NFC (nativ)",   "Spoolman NFC (native)",    "Spoolman NFC (natif)" },  // STR_TF_NATIVE
  { "Vom Server unterstützt", "Supported by the server",  "Pris en charge par le serveur" },  // STR_TF_NATIVE_SUB
  { "Erst ab Spoolman v0.27", "Spoolman v0.27 and later", "À partir de Spoolman v0.27" },  // STR_TF_NATIVE_NA
  { "Spoolman hat inzwischen ein eigenes Tag-Modell, statt einer UID in einem "
    "Extra-Feld. Es ist noch in keiner Version enthalten - diese Zeile wird "
    "erst wählbar, wenn der Server es kann.\n\n"
    "Was es besser macht: eine Spule kann mehrere Tags tragen, ohne Liste in "
    "einem Textfeld. Ein Scan ist eine einzige Anfrage, die die Spule gleich "
    "mitliefert, statt Suche plus Nachprüfung. Und ein Tag, der schon an einer "
    "anderen Spule hängt, wird als solcher gemeldet statt still "
    "überschrieben.\n\n"
    "Die Extra-Felder bleiben trotzdem wählbar: SpoolLink, SpoolSense und "
    "FilaMan schreiben weiter ihre eigenen, und wer eines davon parallel "
    "betreibt, braucht es.",
    "Spoolman has grown a tag model of its own, instead of a UID in an extra "
    "field. No release carries it yet - this entry only becomes selectable "
    "once the server has it.\n\n"
    "What it does better: a spool can hold several tags with no list squeezed "
    "into a text field. A scan is one request that returns the spool with it, "
    "rather than a search plus a verification pass. And a tag that already "
    "belongs to another spool is reported as such instead of being silently "
    "overwritten.\n\n"
    "The extra fields stay selectable regardless: SpoolLink, SpoolSense and "
    "FilaMan keep writing their own, and anyone running one of them alongside "
    "still needs it.",
    "Spoolman gère désormais les tags lui-même, au lieu d'un UID dans un champ supplémentaire. Aucune version publiée ne l'inclut encore - cette ligne ne devient sélectionnable que si le serveur le permet.\n\nAvantages : une bobine peut porter plusieurs tags, sans liste tassée dans un champ texte. Lire un tag ne demande qu'une requête, qui renvoie directement la bobine, au lieu d'une recherche puis d'une vérification. Et un tag déjà lié à une autre bobine est signalé, au lieu d'être écrasé sans prévenir.\n\nLes champs supplémentaires restent malgré tout sélectionnables : SpoolLink, SpoolSense et FilaMan continuent d'écrire dans les leurs, et si vous utilisez l'un d'eux en parallèle, il vous faut son champ." },  // STR_TF_NATIVE_INFO
  { "extra.tag",                 "extra.tag",                "extra.tag" },  // STR_TF_TAG
  { "Diese Waage, OpenSpoolman", "This scale, OpenSpoolman", "Cette balance, OpenSpoolman" },  // STR_TF_TAG_SUB
  { "Das Feld, das diese Waage seit jeher benutzt, und das auch OpenSpoolman "
    "und spoolnymous schreiben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Die Waage legt die UID so ab, wie "
    "sie sie liest - mit Doppelpunkten, bei Bambu-Tags die tray_uuid. "
    "OpenSpoolman legt dort eine eigene UUID ab, die Feldbelegung ist also "
    "gleich, der Inhalt nicht zwingend.\n\n"
    "Die richtige Wahl, wenn nichts dagegen spricht.",
    "The field this scale has always used, and the one OpenSpoolman and "
    "spoolnymous write as well.\n\n"
    "One value per spool, no list format. The scale stores the UID the way it "
    "reads it, with colons, and the tray_uuid for Bambu tags. OpenSpoolman "
    "puts a UUID of its own in there, so the field matches but the contents "
    "need not.\n\n"
    "The right choice unless something speaks against it.",
    "Le champ que cette balance utilise depuis toujours, et où écrivent aussi OpenSpoolman et spoolnymous.\n\nUne seule valeur par bobine, pas de liste. La balance y écrit l'UID en hexadécimal majuscule sans séparateur (la tray_uuid pour un tag Bambu). OpenSpoolman y range son propre identifiant (UUID) : même champ, mais pas forcément même contenu.\n\nLe bon choix, sauf raison contraire." },  // STR_TF_TAG_INFO

  { "extra.nfc_id",                     "extra.nfc_id",                     "extra.nfc_id" },  // STR_TF_NFCID
  { "FilaMan, nfc2klipper, SpoolSense", "FilaMan, nfc2klipper, SpoolSense",
    "FilaMan, nfc2klipper, SpoolSense" },  // STR_TF_NFCID_SUB
  { "Das Feld, auf das sich FilaMan, nfc2klipper und SpoolSense geeinigt "
    "haben.\n\n"
    "Ein Wert pro Spule, kein Listenformat. Erwartet wird reines Hex in "
    "Grossbuchstaben ohne Trenner - die Waage schreibt hier also "
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
    "Le champ sur lequel FilaMan, nfc2klipper et SpoolSense se sont accordés.\n\nUne seule valeur par bobine, pas de liste. Ces logiciels attendent de l'hexadécimal majuscule sans séparateur : la balance écrit donc 04A1B2C3D4E5F6 et non 04:A1:B2:C3:D4:E5:F6, sinon ils ne trouveraient pas l'UID.\n\nUtile si l'un d'eux accède en parallèle à la même base Spoolman." },  // STR_TF_NFCID_INFO

  { "extra.card_uids",         "extra.card_uids",         "extra.card_uids" },  // STR_TF_CARDUIDS
  { "SpoolLink, Snapmaker U1", "SpoolLink, Snapmaker U1", "SpoolLink, Snapmaker U1" },  // STR_TF_CARDUIDS_SUB
  { "Das Feld, das SpoolLink in der Snapmaker-Firmware und Spool Studio "
    "benutzen.\n\n"
    "Das einzige Extra-Feld, das eine Liste aufnimmt: mehrere UIDs, "
    "kommagetrennt, reines Hex in Grossbuchstaben. Beim Snapmaker U1 ist das "
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
    "Le champ qu'utilisent SpoolLink (firmware Snapmaker) et Spool Studio.\n\nLe seul champ supplémentaire qui accepte une liste : plusieurs UID séparés par des virgules, en hexadécimal majuscule. C'est la règle sur le Snapmaker U1 : une bobine porte un tag par flasque, pour se monter d'un côté comme de l'autre de l'imprimante.\n\nParmi les champs supplémentaires, seul celui-ci permet l'option « Lier plusieurs tags ». Spoolman NFC le permet aussi, sans cette option, car plusieurs tags y sont la norme et non un format tassé dans un champ texte. Si vous avez le choix, prenez Spoolman NFC ; ce champ convient si SpoolLink doit tourner en parallèle." },  // STR_TF_CARDUIDS_INFO

  { "Trocknungsdatum", "Drying date", "Date de séchage" },  // STR_EF_LAST_DRIED
  { "Wann die Spule zuletzt getrocknet wurde. Spoolman hat dafür kein eigenes "
    "Feld, deshalb schreibt die Waage es nach extra.last_dried.\n\n"
    "Fehlt das Feld, bleibt die Trocknungsanzeige leer und der Knopf "
    "\"Getrocknet\" kann nichts speichern. Sonst ändert sich nichts.",
    "When the spool was last dried. Spoolman has no field of its own for it, "
    "so the scale writes it to extra.last_dried.\n\n"
    "Without the field the drying line stays empty and the \"Dried\" button "
    "has nowhere to save. Nothing else changes.",
    "Date du dernier séchage de la bobine. Spoolman n'a pas de champ pour cela : la balance l'écrit donc dans extra.last_dried.\n\nSans ce champ, l'indication « Dernier séchage » reste vide et le bouton « Noter le séchage » ne peut rien enregistrer. Rien d'autre ne change." },  // STR_EF_LAST_DRIED_INFO

  { "vorhanden",                   "present",                        "présent" },  // STR_EF_PRESENT
  { "fehlt auf dem Server",        "missing on the server",          "absent du serveur" },  // STR_EF_MISSING
  { "Feld auf dem Server anlegen", "Create the field on the server",
    "Créer le champ sur le serveur" },  // STR_EF_CREATE_ROW
  { "Lade Spulen ...", "Loading spools ...",
    "Chargement des bobines ..." },  // STR_LOADING_SPOOLS
  { "%d Spulen, sortiere ...", "%d spools, sorting ...",
    "%d bobines, tri en cours ..." },  // STR_LOADING_FILTER

  // ── Web interface ─────────────────────────────────────
  { "Status",
    "Status",
    "État" },  // STR_W_NAV_STATUS
  { "Backend",
    "Backend",
    "Backend" },  // STR_W_NAV_BACKEND
  { "Trocknung",
    "Drying",
    "Séchage" },  // STR_W_NAV_DRYING
  { "Tags",
    "Tags",
    "Tags" },  // STR_W_NAV_TAGS
  { "Einstellungen",
    "Settings",
    "Réglages" },  // STR_W_NAV_SETTINGS
  { "Logs",
    "Logs",
    "Journaux" },  // STR_W_NAV_LOGS
  { "Firmware",
    "Firmware",
    "Firmware" },  // STR_W_NAV_FIRMWARE
  { "Keine Verbindung zu Spoolman, FilaMan oder BamBuddy - Open-Source-Projekt",
    "Not affiliated with Spoolman, FilaMan or BamBuddy - Open Source Project",
    "Sans lien avec Spoolman, FilaMan ou BamBuddy - projet open source" },  // STR_W_DISCLAIMER
  { "Speichern",
    "Save",
    "Enregistrer" },  // STR_W_SAVE
  { "Gespeichert",
    "Saved",
    "Enregistré" },  // STR_W_SAVED
  { "Fehler",
    "Error",
    "Erreur" },  // STR_W_ERROR
  { "Auf Standard zurück",
    "Reset to defaults",
    "Rétablir les valeurs par défaut" },  // STR_W_DEFAULTS
  { "%s ist ausgeschaltet",
    "%s is switched off",
    "%s est désactivé" },  // STR_W_OFF_TITLE
  { "Dieser Bereich ist am Gerät abgeschaltet und wird deshalb nicht ausgeliefert.",
    "This section is disabled on the device, so it is not being served.",
    "Cette section est désactivée sur l'appareil, elle n'est donc pas servie." },  // STR_W_OFF_BODY
  { "Hier einschalten:",
    "Turn it on here:",
    "Activez-la ici :" },  // STR_W_OFF_WHERE
  { "Einstellungen &rsaquo; System &rsaquo; Weboberfläche",
    "Settings &rsaquo; System &rsaquo; Web interface",
    "Réglages &rsaquo; Système &rsaquo; Interface web" },  // STR_W_OFF_PATH
  { "Danach diese Seite neu laden.",
    "Then reload this page.",
    "Rechargez ensuite cette page." },  // STR_W_OFF_RELOAD
  { "Zurück zum Status",
    "Back to status",
    "Retour à l'état" },  // STR_W_BACK_STATUS
  { "Netzwerk",
    "Network",
    "Réseau" },  // STR_W_C_NETWORK
  { "Hardware",
    "Hardware",
    "Matériel" },  // STR_W_C_HARDWARE
  { "Bestandsverwaltung",
    "Inventory",
    "Gestion des stocks" },  // STR_W_C_INVENTORY
  { "Zugriff",
    "Access",
    "Accès" },  // STR_W_C_ACCESS
  { "Gerät",
    "Device",
    "Appareil" },  // STR_W_C_DEVICE
  { "WLAN",
    "WiFi",
    "WiFi" },  // STR_W_R_WIFI
  { "Adresse",
    "Address",
    "Adresse" },  // STR_W_R_ADDRESS
  { "Name",
    "Name",
    "Nom" },  // STR_W_R_NAME
  { "Gateway",
    "Gateway",
    "Passerelle" },  // STR_W_R_GATEWAY
  { "Waage",
    "Scale",
    "Balance" },  // STR_W_R_SCALE
  { "NFC-Leser",
    "NFC reader",
    "Lecteur NFC" },  // STR_W_R_NFC
  { "SD-Karte",
    "SD card",
    "Carte SD" },  // STR_W_R_SD
  { "Laufzeit",
    "Uptime",
    "Durée de marche" },  // STR_W_R_UPTIME
  { "Backend",
    "Backend",
    "Backend" },  // STR_W_R_BACKEND
  { "Erreichbar",
    "Reachable",
    "Joignable" },  // STR_W_R_REACHABLE
  { "Tags gescannt",
    "Tags scanned",
    "Tags scannés" },  // STR_W_R_SCANS
  { "Protokoll auf SD-Karte",
    "Log to SD card",
    "Journal sur carte SD" },  // STR_W_R_SDLOG
  { "Ausführliches Protokoll",
    "Verbose logging",
    "Journal détaillé" },  // STR_W_R_VERBOSE
  { "bereit",
    "ready",
    "en service" },  // STR_W_S_READY
  { "fehlt",
    "missing",
    "introuvable" },  // STR_W_S_MISSING
  { "an",
    "on",
    "oui" },  // STR_W_S_ON
  { "aus",
    "off",
    "non" },  // STR_W_S_OFF
  { "ja",
    "yes",
    "oui" },  // STR_W_S_YES
  { "nein",
    "no",
    "non" },  // STR_W_S_NO
  { "nicht verbunden",
    "not connected",
    "hors ligne" },  // STR_W_S_NOWIFI
  { "Was ausgeschaltet ist, wird nicht ausgeliefert - auch die Endpunkte dahinter nicht. Umschalten am Gerät unter",
    "A section that is off is not served at all, and neither are the endpoints behind it. Switch it on the device under",
    "Une section désactivée est totalement inaccessible, y compris par ses adresses d'API. Se règle sur l'appareil, dans" },  // STR_W_ACCESS_NOTE
  { "Neu starten",
    "Restart",
    "Redémarrer" },  // STR_W_RESTART
  { "Alle Einstellungen liegen im NVS, ein Neustart verliert nichts.",
    "Settings are kept in NVS, so a restart loses nothing.",
    "Tous les réglages restent en mémoire permanente : un redémarrage n'en perd aucun." },  // STR_W_RESTART_NOTE
  { "Gerät jetzt neu starten?",
    "Restart the device now?",
    "Redémarrer l'appareil maintenant ?" },  // STR_W_RESTART_ASK
  { "Startet neu",
    "Restarting",
    "Redémarrage" },  // STR_W_RESTARTING
  { "warte auf das Gerät",
    "waiting for the device",
    "attente de l'appareil" },  // STR_W_RESTART_WAIT
  { " (SD-Karte steckt, der Start dauert rund 20 s länger)",
    " (SD card fitted, boot takes about 20s longer)",
    " (carte SD présente, le démarrage prend environ 20 s de plus)" },  // STR_W_RESTART_SD
  { "immer noch am Warten",
    "still waiting",
    "toujours en attente" },  // STR_W_RESTART_LONG
  { "Das Gerät hat nicht geantwortet. Vielleicht ist es nicht mehr im Netz -",
    "The device has not answered. It may be off the network -",
    "L'appareil n'a pas répondu. Il n'est peut-être plus sur le réseau -" },  // STR_W_RESTART_GONE
  { "neu laden",
    "reload",
    "recharger" },  // STR_W_RELOAD
  { "Adresse",
    "Address",
    "Adresse" },  // STR_W_C_BACKEND_ADDR
  { "Adresse des Backends",
    "Backend address",
    "Adresse du backend" },  // STR_W_HOST_LABEL
  { "Hostname oder IP, bei Bedarf mit Port. Ein Name funktioniert auch hinter einem Reverse Proxy, wo die IP allein nicht ans Ziel führt.",
    "Host name or IP, with a port when one is needed. A name also works behind a reverse proxy, where the IP alone does not reach the target.",
    "Nom d'hôte ou adresse IP, avec le port si besoin. Un nom fonctionne aussi derrière un proxy inverse, où l'adresse IP seule ne mène pas au serveur visé." },  // STR_W_HOST_HINT
  { "Ohne Port geht es auf 80. Üblich sind Spoolman 7912, FilaMan 8083, BamBuddy 8000.",
    "Without a port this goes to 80. The usual ones are Spoolman 7912, FilaMan 8083, BamBuddy 8000.",
    "Sans port indiqué, le port 80 est utilisé. Ports habituels : Spoolman 7912, FilaMan 8083, BamBuddy 8000." },  // STR_W_HOST_PORTHINT
  { "Die Adresse darf nicht leer sein.",
    "The address cannot be empty.",
    "L'adresse ne peut pas être vide." },  // STR_W_HOST_EMPTY
  { "https wird noch nicht unterstützt. Die Waage spricht nur http.",
    "https is not supported yet. The scale speaks plain http only.",
    "https n'est pas encore pris en charge. La balance ne parle que http." },  // STR_W_HOST_HTTPS
  { "Verbinde ...",
    "Connecting ...",
    "Connexion ..." },  // STR_W_HOST_TESTING
  { "Erreichbar",
    "Reachable",
    "Joignable" },  // STR_W_HOST_OK
  { "Nicht erreichbar",
    "Not reachable",
    "Injoignable" },  // STR_W_HOST_FAIL
  { "Zugangsdaten",
    "Credentials",
    "Identifiants" },  // STR_W_C_CREDS
  { "API-Key",
    "API key",
    "Clé d'API" },  // STR_W_APIKEY
  { "Gerätecode",
    "Device code",
    "Code d'appareil" },  // STR_W_DEVICE_CODE
  { "Registrieren",
    "Register",
    "Associer l'appareil" },  // STR_W_REGISTER
  { "hinterlegt",
    "set",
    "en mémoire" },  // STR_W_SET
  { "fehlt",
    "missing",
    "à définir" },  // STR_W_UNSET
  { "Spoolman braucht keine Zugangsdaten.",
    "Spoolman needs no credentials.",
    "Spoolman n'a besoin d'aucun identifiant." },  // STR_W_NO_CREDS
  { "Schwellwerte je Material",
    "Thresholds per material",
    "Seuils par matériau" },  // STR_W_C_DRYING
  { "Material",
    "Material",
    "Matériau" },  // STR_W_DRY_MATERIAL
  { "Gelb ab",
    "Amber after",
    "Jaune dès" },  // STR_W_DRY_YELLOW
  { "Rot ab",
    "Red after",
    "Rouge dès" },  // STR_W_DRY_RED
  { "Lagerung",
    "Storage",
    "Stockage" },  // STR_W_DRY_STORAGE
  { "trocken",
    "sealed",
    "sous vide" },  // STR_W_DRY_SEALED
  { "Tage",
    "days",
    "jours" },  // STR_W_DRY_DAYS
  { "Faktor für trockene Lagerung",
    "Multiplier for sealed storage",
    "Facteur pour un stockage sous vide" },  // STR_W_DRY_MULT
  { "Luftdicht gelagert hält Filament länger. Die Schwellwerte oben werden für diese Materialien mit dem Faktor multipliziert.",
    "Filament stored airtight lasts longer. The thresholds above are multiplied by this factor for those materials.",
    "Stocké à l'abri de l'air, le filament se conserve plus longtemps. Pour les matériaux marqués « sous vide », les seuils ci-dessus sont multipliés par ce facteur." },  // STR_W_DRY_MULT_HINT
  { "Gerätename",
    "Device name",
    "Nom de l'appareil" },  // STR_W_C_DEVNAME
  { "Name oder ganze Adresse, zum Beispiel scale.home.arpa. Der Teil vor dem ersten Punkt ist auch der Name, den der Router zeigt.",
    "A name, or a whole address such as scale.home.arpa. The part before the first dot is also the name your router shows.",
    "Un nom, ou une adresse complète comme scale.home.arpa. La partie avant le premier point est aussi le nom que votre routeur affiche." },  // STR_W_DEVNAME_HINT
  { "Buchstaben, Ziffern und Bindestriche, durch Punkte getrennt. Kein Bindestrich am Anfang oder Ende, keine Leerzeichen, kein leerer Teil zwischen zwei Punkten.",
    "Letters, digits and hyphens, separated by dots. No hyphen at the start or end, no spaces, no empty part between two dots.",
    "Lettres, chiffres et traits d'union, séparés par des points. Pas de trait d'union au début ni à la fin, pas d'espace, aucune partie vide entre deux points." },  // STR_W_DEVNAME_BAD
  { "Jetzt erreichbar unter %s - beim Router nach dem nächsten Verbinden.",
    "Reachable now at %s - the router shows it after the next connection.",
    "Joignable maintenant à %s - le routeur l'affiche après la prochaine connexion." },  // STR_W_DEVNAME_NOW
  { "Listenlimits",
    "List limits",
    "Limites de liste" },  // STR_W_C_LIMITS
  { "Spulenliste",
    "Spool list",
    "Liste des bobines" },  // STR_W_LIMIT_SPOOLS
  { "Standortliste",
    "Location list",
    "Liste des emplacements" },  // STR_W_LIMIT_LOCS
  { "Wie viele Einträge die Auswahl am Gerät zeigt.",
    "How many entries the picker on the device shows.",
    "Nombre maximal d'entrées affichées dans la liste de l'appareil." },  // STR_W_LIMIT_HINT
  { "Zu viele Einträge lassen die Anzeige einfrieren - ein Neustart erfolgt nicht von selbst.",
    "Too many entries freeze the display - it does not reboot by itself.",
    "Trop d'entrées figent l'affichage - et l'appareil ne redémarre pas de lui-même." },  // STR_W_LIMIT_WARN
  { "Anzeige",
    "Display",
    "Affichage" },  // STR_W_C_DISPLAY
  { "Helligkeitsanhebung",
    "Brightness lift",
    "Renfort de luminosité" },  // STR_W_GAIN
  { "100 ist aus. Die Hintergrundbeleuchtung ist bei 255 schon am Anschlag, das hier ist der verbleibende Hebel auf ein dunkles Panel.",
    "100 is off. The backlight is already at its ceiling at 255, so this is the only remaining lever on a dim panel.",
    "À 100, aucun renfort. Le rétroéclairage plafonne déjà à 255 : ce renfort reste le seul moyen d'éclaircir un écran trop sombre." },  // STR_W_GAIN_HINT
  { "Tag beschreiben",
    "Write a tag",
    "Écrire un tag" },  // STR_W_C_WRITETAG
  { "Spule",
    "Spool",
    "Bobine" },  // STR_W_TAG_SPOOL
  { "-- Spule wählen --",
    "-- pick a spool --",
    "-- choisir une bobine --" },  // STR_W_TAG_PICK
  { "Auf dem Tag",
    "On the tag",
    "Sur le tag" },  // STR_W_TAG_ONTAG
  { "Würde geschrieben",
    "Will be written",
    "Sera écrit" },  // STR_W_TAG_WILLBE
  { "Kein Tag auf dem Leser.",
    "No tag on the reader.",
    "Aucun tag sur le lecteur." },  // STR_W_TAG_NOTAG
  { "Tag auf dem Leser:",
    "Tag on the reader:",
    "Tag sur le lecteur :" },  // STR_W_TAG_ONREADER
  { "Erst eine Spule wählen.",
    "Pick a spool first.",
    "Choisissez d'abord une bobine." },  // STR_W_TAG_PICKFIRST
  { "Leerer Tag",
    "Blank tag",
    "Tag vierge" },  // STR_W_TAG_BLANK
  { "Daten, die diese Firmware nicht lesen kann",
    "Data this firmware cannot read",
    "Données que ce firmware ne sait pas lire" },  // STR_W_TAG_UNKNOWN
  { "Tag beschreiben",
    "Write tag",
    "Écrire le tag" },  // STR_W_TAG_WRITE
  { "Tag überschreiben",
    "Overwrite tag",
    "Écraser le tag" },  // STR_W_TAG_OVERWRITE
  { "Tag stimmt bereits überein",
    "Tag already matches",
    "Le tag correspond déjà" },  // STR_W_TAG_MATCHES
  { "Tag leeren",
    "Erase tag",
    "Vider le tag" },  // STR_W_TAG_ERASE
  { "Alles auf diesem Tag löschen?",
    "Erase everything on this tag?",
    "Effacer tout ce qui est sur ce tag ?" },  // STR_W_TAG_ERASE_ASK
  { "Spule mit diesem Tag verknüpfen",
    "Link the spool to this tag",
    "Lier la bobine à ce tag" },  // STR_W_TAG_LINK
  { "Diese Spule hängt an %s, das damit zum vorherigen Tag wird.",
    "This spool is linked to %s, which becomes its previous tag.",
    "Cette bobine est liée à %s, qui devient son tag précédent." },  // STR_W_TAG_RELINK
  { "Eingereiht.",
    "Queued.",
    "En file d'attente." },  // STR_W_TAG_QUEUED
  { "Spulenliste nicht verfügbar",
    "Spool list unavailable",
    "Liste indisponible" },  // STR_W_TAG_NOLIST
  { "SKU",
    "SKU",
    "Référence" },  // STR_W_TAG_SKU
  { "Düse",
    "Nozzle",
    "Buse" },  // STR_W_TAG_NOZZLE
  { "Bett",
    "Bed",
    "Plateau" },  // STR_W_TAG_BED
  { "Gewicht",
    "Weight",
    "Poids" },  // STR_W_TAG_WEIGHT
  { "Durchmesser",
    "Diameter",
    "Diamètre" },  // STR_W_TAG_DIA
  { "Länge",
    "Length",
    "Longueur" },  // STR_W_TAG_LENGTH
  { "Links steht, was gerade auf dem Tag liegt, rechts, was die gewählte Spule ergäbe. Abweichende Zeilen sind farbig.",
    "On the left what the tag holds right now, on the right what the selected spool would put there. Lines that differ are coloured.",
    "À gauche, ce que le tag contient en ce moment ; à droite, ce que la bobine choisie y mettrait. Les lignes qui diffèrent sont en couleur." },  // STR_W_TAG_COMPARE
  { "SD-Karte",
    "SD card",
    "Carte SD" },  // STR_W_C_LOGS
  { "Ansehen",
    "View",
    "Voir" },  // STR_W_LOG_VIEW
  { "Löschen",
    "Delete",
    "Supprimer" },  // STR_W_LOG_DELETE
  { "Diese Datei löschen?",
    "Delete this file?",
    "Supprimer ce fichier ?" },  // STR_W_LOG_DELETE_ASK
  { "Keine SD-Karte erkannt",
    "No SD card detected",
    "Aucune carte SD détectée" },  // STR_W_LOG_NOSD
  { "Eine FAT32-formatierte Karte einlegen, um die Diagnoseprotokolle zu aktivieren.",
    "Insert a FAT32 formatted card to enable diagnostic logging.",
    "Insérez une carte formatée en FAT32 pour activer les journaux de diagnostic." },  // STR_W_LOG_NOSD_HINT
  { "Noch keine Protokolle.",
    "No logs yet.",
    "Aucun journal pour l'instant." },  // STR_W_LOG_EMPTY
  { "Firmware",
    "Firmware",
    "Firmware" },  // STR_W_C_FIRMWARE
  { "Installiert",
    "Installed",
    "Version installée" },  // STR_W_FW_INSTALLED
  { "Datei hochladen",
    "Upload a file",
    "Envoyer un fichier" },  // STR_W_FW_FILE
  { "Flashen",
    "Flash",
    "Flasher" },  // STR_W_FW_FLASH
  { "Das Gerät startet nach dem Schreiben von selbst neu. Strom nicht trennen.",
    "The device restarts by itself once written. Do not cut the power.",
    "Après l'écriture du firmware, l'appareil redémarre de lui-même. Ne coupez pas l'alimentation." },  // STR_W_FW_HINT
  { "Update erfolgreich",
    "Update successful",
    "Mise à jour réussie" },  // STR_W_FW_OK
  { "Das Gerät startet neu ...",
    "Device is restarting ...",
    "L'appareil redémarre ..." },  // STR_W_FW_RESTARTING
  { "Update fehlgeschlagen",
    "Update failed",
    "Échec de la mise à jour" },  // STR_W_FW_FAIL
  { "Bitte erneut versuchen.",
    "Please try again.",
    "Veuillez réessayer." },  // STR_W_FW_RETRY
  { "Update über GitHub",
    "Update from GitHub",
    "Mise à jour par GitHub" },  // STR_W_C_FW_GITHUB
  { "Kanal",
    "Channel",
    "Canal" },  // STR_W_FW_CHANNEL
  { "Release",
    "Release",
    "Version stable" },  // STR_W_FW_CH_STABLE
  { "Vorabversion",
    "Pre-release",
    "Pré-version" },  // STR_W_FW_CH_PRE
  { "Neueste",
    "Latest",
    "Dernière version" },  // STR_W_FW_LATEST
  { "Nach Updates suchen",
    "Check for updates",
    "Rechercher des mises à jour" },  // STR_W_FW_CHECK
  { "Suche ...",
    "Checking ...",
    "Recherche ..." },  // STR_W_FW_CHECKING
  { "Bereits aktuell",
    "Already up to date",
    "Déjà à jour" },  // STR_W_FW_UPTODATE
  { "Update verfügbar",
    "Update available",
    "Mise à jour disponible" },  // STR_W_FW_AVAIL
  { "Installieren",
    "Install",
    "Installer" },  // STR_W_FW_INSTALL
  { "Wird installiert ...",
    "Installing ...",
    "Installation ..." },  // STR_W_FW_INSTALLING
  { "Kein WLAN",
    "No WiFi connection",
    "Pas de connexion WiFi" },  // STR_W_FW_NOWIFI
  { "Das Gerät prüft oder schreibt gerade",
    "The device is already checking or writing",
    "L'appareil est déjà en train de chercher ou d'écrire" },  // STR_W_FW_BUSY
  { "Suche fehlgeschlagen",
    "Check failed",
    "Échec de la recherche" },  // STR_W_FW_CHECK_FAIL
  { "Der Kanal ist derselbe wie am Gerät. Das Image wird vom Gerät geladen, nicht vom Browser.",
    "The channel is the same setting as on the device. The image is fetched by the device, not by this browser.",
    "Le canal est le même réglage que sur l'appareil. C'est l'appareil qui télécharge le firmware, pas ce navigateur." },  // STR_W_FW_GH_HINT
  { "Veröffentlicht",
    "Released",
    "Publiée le" },  // STR_W_FW_RELEASED
  { "Installiert am",
    "Installed on",
    "Installée le" },  // STR_W_FW_SINCE
  { "Release Notes",
    "Release notes",
    "Notes de version" },  // STR_W_FW_NOTES
  { "Was ist neu",
    "What is new",
    "Nouveautés" },  // STR_W_FW_WHATSNEW
  { "Nicht als Release veröffentlicht",
    "Not a published release",
    "Version non publiée" },  // STR_W_FW_UNPUBLISHED
  { "unbekannt",
    "unknown",
    "inconnue" },  // STR_W_FW_UNKNOWN
  { "Ausblenden",
    "Hide",
    "Masquer" },  // STR_W_FW_HIDE
  { "{v} installieren?",
    "Install {v}?",
    "Installer {v} ?" },  // STR_W_FW_CONFIRM
  { "Das Gerät startet nach dem Download automatisch neu, die Seite lädt sich dann selbst. Strom nicht trennen.",
    "The device restarts by itself when the download finishes, and this page reloads. Do not cut the power.",
    "L'appareil redémarre tout seul à la fin du téléchargement, et cette page se recharge. Ne coupez pas l'alimentation." },  // STR_W_FW_REBOOTS
  { "Ältere Version",
    "Older release",
    "Version plus ancienne" },  // STR_W_FW_OLDER
  { "Auf {v} zurückstufen?",
    "Downgrade to {v}?",
    "Revenir à {v} ?" },  // STR_W_FW_DOWNGRADE
  { "{v} ist älter als die installierte {i}.",
    "{v} is older than the installed {i}.",
    "{v} est plus ancienne que la version installée {i}." },  // STR_W_FW_DOWNWARN
  { "Gewicht",
    "Weight",
    "Poids" },  // STR_W_R_WEIGHT
  { "Konnte nicht geladen werden.",
    "Could not be loaded.",
    "Chargement impossible." },  // STR_W_LOAD_FAIL
  { "Jede Zeile auf der Karte ist ein eigener Schreibzugriff. Läuft alles rund, lässt sich das Protokoll oben abschalten, ohne die Karte zu ziehen. Das Sitzungsprotokoll weiter unten läuft immer weiter.",
    "Every line on the card is a write of its own. When everything runs fine, switch the log off above instead of pulling the card. The session log further down keeps running either way.",
    "Chaque ligne du journal est une écriture distincte sur la carte. Quand tout fonctionne bien, désactivez le journal ci-dessus plutôt que de retirer la carte. Le journal de session, plus bas, continue dans tous les cas." },  // STR_W_LOG_NOTE
  { "Sitzungsprotokoll",
    "Session log",
    "Journal de session" },  // STR_W_C_SESSION
  { "Die letzten Zeilen seit dem Start, im Arbeitsspeicher gehalten und beim Neustart weg. Eine SD-Karte braucht es nur, um Protokolle zu behalten.",
    "The last lines since start, held in memory and gone on restart. An SD card is only needed to keep logs, not to have them.",
    "Les dernières lignes du journal depuis le démarrage, gardées en mémoire vive et perdues à chaque redémarrage. Une carte SD n'est nécessaire que pour conserver les journaux." },  // STR_W_SESSION_NOTE
  { "Noch nichts protokolliert.",
    "Nothing logged yet.",
    "Rien de journalisé pour l'instant." },  // STR_W_SESSION_EMPTY
  { "Aktualisieren",
    "Refresh",
    "Actualiser" },  // STR_W_SESSION_REFRESH
  { "Wird geladen...",
    "Loading...",
    "Chargement..." },  // STR_W_SESSION_BUSY
  { "Geholt um",
    "Fetched at",
    "Récupéré à" },  // STR_W_SESSION_UPDATED
  { "Zeilen",
    "lines",
    "lignes" },  // STR_W_SESSION_LINES
  { "Angehalten, zum Weiterlesen auf Aktualisieren tippen",
    "Paused, press refresh to follow again",
    "En pause, touchez Actualiser pour reprendre le suivi" },  // STR_W_SESSION_PAUSED
  { "neu",
    "new",
    "nouvelles" },  // STR_W_SESSION_NEW
  { "Text kopieren",
    "Copy text",
    "Copier" },  // STR_W_SESSION_COPY
  { "Kopiert",
    "Copied",
    "Copié" },  // STR_W_SESSION_COPIED
  { "Kopieren nicht moeglich, bitte markieren",
    "Cannot copy, please select the text",
    "Copie impossible, sélectionnez le texte" },  // STR_W_SESSION_COPYFAIL
  { "Einen beschreibbaren NTAG auflegen, Spule wählen, schreiben. Was auf dem Tag steht, wird ersetzt. Tags ab Werk sind meist MIFARE Classic oder gesperrt und lassen sich nur lesen.",
    "Place a writable NTAG on the reader, pick a spool, and write it. Whatever is already on the tag is replaced. Factory tags are usually MIFARE Classic or locked, and can only be read.",
    "Posez un NTAG inscriptible sur le lecteur, choisissez une bobine, puis cliquez sur Écrire le tag. Tout ce que contient déjà le tag est remplacé. Les tags posés en usine sont le plus souvent des MIFARE Classic ou sont verrouillés : ils ne peuvent qu'être lus." },  // STR_W_TAG_NOTE
  { "<b>Welcher Tag für welches Format.</b> OpenSpool braucht rund 180 Byte und damit einen <b>NTAG215</b> (496 Byte) oder <b>NTAG216</b> (872 Byte). Auf einen NTAG213 (144 Byte) passt davon nichts, dort geht nur Anycubic ACE, das mit 112 Byte auskommt. Meldet ein Tag keine Größe, rechnet die Waage sicherheitshalber mit den 144 Byte eines NTAG213 - dann den Tag einmal mit einer NFC-App als NDEF formatieren, das trägt die Größe ein.",
    "<b>Which tag for which format.</b> OpenSpool needs about 180 bytes, so it wants an <b>NTAG215</b> (496 bytes) or an <b>NTAG216</b> (872 bytes). None of it fits an NTAG213 (144 bytes), which leaves Anycubic ACE, and that needs only 112. A tag that reports no size at all is treated as the 144 bytes of an NTAG213 to stay safe - format such a tag as NDEF once with any NFC app and it will report its real size.",
    "<b>Quel tag pour quel format.</b> OpenSpool a besoin d'environ 180 octets, donc d'un <b>NTAG215</b> (496 octets) ou d'un <b>NTAG216</b> (872 octets). Un NTAG213 (144 octets) est trop petit pour OpenSpool : seul le format Anycubic ACE, qui se contente de 112 octets, y tient. Si un tag n'indique pas sa taille, la balance suppose par prudence qu'il n'a que 144 octets, comme un NTAG213 - dans ce cas, formatez-le une fois en NDEF avec une application NFC, ce qui y inscrit sa taille." },  // STR_W_TAG_SIZES
  { "FilaMan legt beides an verschiedenen Stellen an und zeigt es jeweils nur einmal.<br><b>API-Key:</b> auf das Zahnrad neben dem Benutzernamen klicken, <b>API Keys</b> öffnen und einen Key erstellen. Oben eintragen und speichern.<br><b>Gerätecode:</b> <b>Admin-Bereich &gt; Geräte</b> öffnen und <b>Gerät erstellen</b> klicken. Den sechsstelligen Code oben eintragen und registrieren.<br>Ein Gerät anlegen kann nur ein Admin. Den Key mit demselben Konto erstellen, sonst lehnt FilaMan die AMS-Zuordnung ab.",
    "FilaMan creates the two in different places and shows each only once.<br><b>API key:</b> click the gear icon next to your user name, open <b>API Keys</b> and create a key. Enter it above and save.<br><b>Device code:</b> open <b>Admin Panel &gt; Devices</b> and click <b>Create Device</b>. Enter the six character code above and register.<br>Only an admin can create a device. Create the key with the same account, or FilaMan refuses the AMS assignment.",
    "FilaMan crée la clé et le code à deux endroits différents, et n'affiche chacun qu'une seule fois.<br><b>Clé d'API :</b> cliquez sur l'icône d'engrenage à côté de votre nom d'utilisateur, ouvrez <b>Clés API</b> (API Keys) et créez une clé. Saisissez-la ci-dessus et cliquez sur Enregistrer.<br><b>Code d'appareil :</b> ouvrez <b>Espace admin &gt; Appareils</b> (Admin Panel > Devices) et cliquez sur <b>Créer un appareil</b> (Create Device). Saisissez le code à six caractères ci-dessus, puis cliquez sur Associer l'appareil.<br>Seul un administrateur peut créer un appareil. Créez la clé avec ce même compte, sinon FilaMan refuse l'affectation AMS." },  // STR_W_FM_SETUP
  { "Der Schlüssel steht in BamBuddy unter den Einstellungen. Läuft die Instanz ohne Anmeldung, bleibt das Feld leer.",
    "The key is in BamBuddy under settings. Leave the field empty if the instance runs without authentication.",
    "La clé se trouve dans BamBuddy, dans les réglages. Laissez le champ vide si l'instance tourne sans authentification." },  // STR_W_BB_SETUP
  { "Strom nicht trennen",
    "Do not cut the power",
    "Ne coupez pas l'alimentation" },  // STR_OTA_KEEP_POWER
  { "Kaffee ausgeben",
    "Buy me a coffee",
    "Offrir un café" },  // STR_W_KOFI
  { "Adresse ist ein Name",
    "Address is a name",
    "L'adresse est un nom" },  // STR_SP_LOCKED_TITLE
  { "Dieser Ziffernblock kann nur Zahlen. Die Adresse im Browser ändern:",
    "This keypad can only make numbers. Change the address in the browser:",
    "Cet écran ne permet de saisir que des chiffres. Modifiez l'adresse depuis un navigateur :" },  // STR_SP_LOCKED_INFO
  { "Weboberfläche aus: Einstellungen > System > Weboberfläche",
    "Web interface off: Settings > System > Web interface",
    "Désactivée : Réglages > Système > Interface web" },  // STR_SP_WEB_OFF
  { "Adresse leeren",
    "Clear address",
    "Effacer l'adresse" },  // STR_SP_CLEAR
  { "Adresse verwerfen? Danach ist das Backend nicht mehr eingerichtet, und am Gerät lässt sich nur eine IP eingeben.",
    "Discard the address? The backend is then no longer set up, and the device itself can only enter an IP.",
    "Effacer l'adresse ? Le backend ne sera plus configuré, et sur l'appareil seule une adresse IP pourra être saisie." },  // STR_SP_CLEAR_ASK
  { "Alle löschen",
    "Delete all",
    "Tout supprimer" },  // STR_W_LOG_DELETE_ALL
  { "{n} Dateien löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete {n} files? Today's log is started over.",
    "Supprimer {n} fichiers ? Le journal du jour est recommencé." },  // STR_W_LOG_DELETE_ALL_ASK
  { "{n} Dateien",
    "{n} files",
    "{n} fichiers" },  // STR_W_LOG_COUNT
  // Its own entry rather than a rule in code: which counts need their own
  // wording is a property of the language, not of the list.
  { "1 Datei",
    "1 file",
    "1 fichier" },  // STR_W_LOG_COUNT_ONE
  { "Eine Datei löschen? Das Log von heute wird dabei neu begonnen.",
    "Delete one file? Today's log is started over.",
    "Supprimer un fichier ? Le journal du jour est recommencé." },  // STR_W_LOG_DELETE_ALL_ASK_ONE
  { "Zeitzone",
    "Time zone",
    "Fuseau horaire" },  // STR_TZ_TITLE
  { "Gilt für jeden Zeitstempel des Geräts und für die Zählung der Trocknungstage. Kein Neustart nötig.",
    "Applies to every timestamp the device writes and to the drying day count. No restart needed.",
    "S'applique aux dates et heures notées par l'appareil et au décompte des jours depuis le dernier séchage. Sans redémarrage." },  // STR_TZ_HINT
  { "Gilt für jeden Zeitstempel des Geräts und für die Zählung der Trocknungstage. Wirkt sofort, ohne Neustart.",
    "Applies to every timestamp the device writes and to the drying day count. Takes effect at once, no restart.",
    "S'applique aux dates et heures notées par l'appareil et au décompte des jours depuis le dernier séchage. Effet immédiat, sans redémarrage." },  // STR_W_TZ_NOTE

  { "Felder",
    "Fields",
    "Champs" },  // STR_FLM_FIELDS
  { "wohin der Tag geschrieben wird",
    "where the tag is written",
    "où le tag est écrit" },  // STR_FLM_FIELDS_SUB
  { "FilaMan hat ein eigenes Feld für NFC-Tags, und die Waage benutzt es. Daneben führt das Bambu-Lab-Plugin zwei Felder für die RFID-Chips einer Bambu-Spule und merkt sich die Tray-UUID in external_id.\n\nGelesen werden alle vier, immer und ohne Schalter: eine Spule, die der Drucker kennt, soll die Waage auch erkennen. Geschrieben wird nur, was hier eingeschaltet ist.",
    "FilaMan has a field of its own for NFC tags and the scale uses it. Alongside it the Bambu Lab plugin keeps two fields for the RFID chips of a Bambu spool, and remembers the tray uuid in external_id.\n\nAll four are read, always and without a switch: a spool the printer knows is a spool this scale should recognise. Only what is switched on here is written.",
    "FilaMan possède son propre champ pour les tags NFC, et la balance l'utilise. Le module Bambu Lab gère en outre deux champs pour les puces RFID d'une bobine Bambu, et enregistre son identifiant Tray-UUID dans external_id.\n\nCes quatre champs sont lus dans tous les cas : une bobine connue de l'imprimante doit aussi être reconnue par la balance. Seul ce qui est activé ici est écrit." },  // STR_FLM_FIELDS_INFO

  { "Tag-Feld",
    "Tag field",
    "Champ du tag" },  // STR_FLM_TAGFIELD
  { "Anders als bei Spoolman gibt es hier nichts zu wählen, und das ist gut so. rfid_uid ist FilaMans eigenes Feld für genau diesen Zweck, es ist das einzige, das die Server-Suche durchsucht, und das Bambu-Plugin fasst es laut eigener Zusage nie an.\n\nEin Ausweichfeld würde jeden Scan vom Schnellpfad auf den vollen Inventar-Scan werfen: unter 1 kB gegen 176 kB bei 280 Spulen.",
    "Unlike Spoolman there is nothing to choose here, and that is a good thing. rfid_uid is FilaMan's own field for exactly this, it is the only one the server side search covers, and the Bambu plugin never touches it - its own documentation says so.\n\nWriting somewhere else would drop every scan from the fast path to a full inventory load: under 1 kB against 176 kB on a library of 280.",
    "Contrairement à Spoolman, il n'y a rien à choisir ici, et c'est une bonne chose. rfid_uid est le champ prévu par FilaMan pour cet usage : c'est le seul que la recherche du serveur parcourt, et le module Bambu s'engage à ne jamais y toucher.\n\nAvec un autre champ, chaque lecture de tag obligerait à télécharger tout l'inventaire au lieu d'une simple recherche : 176 ko au lieu de moins de 1 ko pour 280 bobines." },  // STR_FLM_TAGFIELD_INFO

  { "Bambu-Tag-Felder pflegen",
    "Maintain the Bambu tag fields",
    "Mettre à jour les champs Bambu" },  // STR_FLM_BTAGS
  { "Chip-UID in den ersten freien Slot",
    "chip uid into the first free slot",
    "UID de puce dans le premier champ libre" },  // STR_FLM_BTAGS_SUB
  { "Eine Bambu-Spule trägt zwei RFID-Chips, einen je Seite. Das Plugin füllt nur den ersten der beiden Felder, mit dem, was der Drucker gemeldet hat; den zweiten hält es für einen weiteren Leser frei.\n\nAn: die Waage trägt die Chip-UID der aufliegenden Seite in den ersten freien der beiden Slots ein. Ein belegter Slot wird nie überschrieben. Legt man beide Seiten auf, sind danach beide gefüllt.\n\nNutzen: die Spule wird auch dann gefunden, wenn sich ihr Tag nicht entschlüsseln lässt und nur seine Chip-UID hergibt.",
    "A Bambu spool carries two RFID chips, one per flange. The plugin fills only the first of the two fields, with what the printer reported, and keeps the second free for another reader.\n\nOn: the scale writes the chip uid of the side on the reader into the first free of the two slots. A slot that holds something is never overwritten. Present both sides and both end up filled.\n\nWhat it buys: the spool is still found when its tag will not decrypt and has nothing but its chip uid to offer.",
    "Une bobine Bambu porte deux puces RFID, une de chaque côté. Le module Bambu ne remplit que le premier des deux champs, avec ce que l'imprimante a signalé, et laisse le second libre pour un autre lecteur.\n\nActivé : la balance inscrit l'identifiant (UID) de la puce posée sur le lecteur dans le premier des deux champs resté vide. Un champ rempli n'est jamais écrasé. Posez un côté puis l'autre : les deux seront remplis.\n\nIntérêt : la bobine est retrouvée même si son tag ne peut pas être déchiffré et ne fournit que l'UID de sa puce." },  // STR_FLM_BTAGS_INFO

  { "external_id mitschreiben",
    "Write external_id too",
    "Écrire aussi external_id" },  // STR_FLM_EXTID
  { "verhindert doppelte Spulen",
    "stops duplicate spools",
    "évite les bobines en double" },  // STR_FLM_EXTID_SUB
  { "Das Bambu-Plugin prüft vor dem Anlegen einer Spule nur external_id. Eine von der Waage verknüpfte Spule trägt die Tray-UUID aber in rfid_uid und ist für diese Prüfung unsichtbar - sie wird ein zweites Mal angelegt.\n\nAn: die Waage trägt bambulab:<Tray-UUID> nach, solange das Feld leer ist. Damit hören die Doppel auf.\n\nDer Preis: das Plugin behandelt die Spule danach als seine und schreibt das Restgewicht aus der AMS-Schätzung fort. Bis zur nächsten Wägung steht dann eine Schätzung dort, wo ein gemessener Wert stand.",
    "Before creating a spool the Bambu plugin looks at external_id and nothing else. A spool linked by this scale carries the tray uuid in rfid_uid instead and is invisible to that check, so it gets created a second time.\n\nOn: the scale fills in bambulab:<tray uuid> while the field is empty. That ends the duplicates.\n\nThe price: the plugin then treats the spool as its own and maintains the remaining weight from the AMS estimate. Until the next weighing an estimate stands where a measured value stood.",
    "Avant de créer une bobine, le module Bambu ne vérifie que external_id. Or une bobine liée par la balance porte l'identifiant Tray-UUID dans rfid_uid : ce contrôle ne la voit pas, et elle est créée une seconde fois.\n\nActivé : la balance inscrit bambulab:<Tray-UUID> tant que le champ est vide. Il n'y a plus de doublons.\n\nL'inconvénient : le module considère ensuite la bobine comme la sienne et met à jour son poids restant d'après l'estimation de l'AMS. Jusqu'à la pesée suivante, ce poids est une estimation et non une mesure." },  // STR_FLM_EXTID_INFO

  { "Tag gefunden - mehrere Spulen",
    "Tag found - several spools",
    "Tag trouvé - plusieurs bobines" },  // STR_TAG_FOUND_DUP

  // ---- device name --------------------------------------------------
  { "mDNS",
    "mDNS",
    "mDNS" },  // STR_W_R_MDNS
  { "Auch erreichbar über",
    "Also reachable at",
    "Également joignable à" },  // STR_W_DEVNAME_ALSO
  { "wird geprüft ...",
    "checking ...",
    "vérification ..." },  // STR_W_DEVNAME_DNS_WAIT
  { "Der Name wird in deinem Netz aufgelöst und zeigt auf diese Waage.",
    "This name resolves on your network and points at this scale.",
    "Ce nom est résolu sur votre réseau et pointe vers cette balance." },  // STR_W_DEVNAME_DNS_OK
  { "Der Name zeigt auf %s, nicht auf diese Waage.",
    "This name points at %s, not at this scale.",
    "Ce nom pointe vers %s, pas vers cette balance." },  // STR_W_DEVNAME_DNS_OTHER
  { "Dein DNS-Server kennt diesen Namen nicht.",
    "Your DNS server does not know this name.",
    "Votre serveur DNS ne connaît pas ce nom." },  // STR_W_DEVNAME_DNS_NONE
  { "Im lokalen Netz auf .local antworten (mDNS)",
    "Answer to .local on the local network (mDNS)",
    "Répondre en .local sur le réseau local (mDNS)" },  // STR_W_MDNS
  { "Findet die Waage ohne DNS-Server. Aus, wenn in deinem Netz kein .local laufen soll.",
    "Finds the scale with no DNS server involved. Off if your network should carry no .local traffic.",
    "Permet de trouver la balance sans serveur DNS. À désactiver si vous ne voulez pas de noms en .local sur votre réseau." },  // STR_W_MDNS_HINT

  // Spool status (FilaMan). Id 6 is covered by STR_ARCHIVED above.
  { "Status wählen", "Select status", "Choisir le statut" },  // STR_STATUS_TITLE
  { "Neu",           "New",           "Neuve" },  // STR_STATUS_NEW
  { "Geöffnet",      "Opened",        "Ouverte" },  // STR_STATUS_OPENED
  { "Trocknet",      "Drying",        "Séchage" },  // STR_STATUS_DRYING
  { "Aktiv",         "Active",        "Active" },  // STR_STATUS_ACTIVE
  { "Leer",          "Empty",         "Vide" },  // STR_STATUS_EMPTY
  { "Unbekannt",     "Unknown",       "Inconnu" },  // STR_STATUS_UNKNOWN

  // Writing a tag
  { "Beschreiben + verknüpfen", "Write + link", "Écrire + lier" },  // STR_REMOTE_LINK_WRITE
  { "Tag im Format %s beschreiben und mit dieser Spule verknüpfen?",
    "Write the tag as %s and link it to this spool?",
    "Écrire le tag en %s et le lier à la bobine ?" },  // STR_REMOTE_LINK_Q_WRITE
  { "Tag beschreiben?", "Write tag?", "Écrire le tag ?" },  // STR_TW_ASK_TITLE
  { "Der Tag wird im Format %s beschrieben. Was jetzt darauf steht, geht verloren.",
    "The tag is written as %s. Whatever is on it now is lost.",
    "Le tag sera écrit au format %s. Son contenu actuel sera perdu." },  // STR_TW_ASK_HINT
  { "Beschreiben",               "Write",                      "Écrire" },  // STR_TW_BTN_WRITE
  { "Nicht jetzt",               "Not now",                    "Pas maintenant" },  // STR_TW_BTN_SKIP
  { "Tag beschrieben",           "Tag written",                "Tag écrit" },  // STR_TW_OK
  { "Kein Tag auf dem Leser",    "No tag on the reader",       "Aucun tag sur le lecteur" },  // STR_TW_ERR_NO_TAG
  { "Dieser Tag ist nur lesbar", "This tag can only be read",
    "Ce tag est en lecture seule" },  // STR_TW_ERR_NOT_NTAG
  { "Spule nicht abrufbar", "Spool could not be fetched",
    "Impossible de lire la bobine sur le serveur" },  // STR_TW_ERR_BACKEND
  { "Der Tag ist zu klein für dieses Format. OpenSpool braucht einen NTAG215 mit 496 Byte, ein NTAG213 hat nur 144. Die Spule ist trotzdem mit dem Tag verknüpft - sie wird also erkannt, der Tag trägt nur keine Daten.",
    "This tag is too small for the format. OpenSpool wants an NTAG215 with 496 bytes, an NTAG213 holds only 144. The spool is linked to the tag all the same, so it is still recognised - the tag just carries no data.",
    "Ce tag est trop petit pour ce format. OpenSpool demande un NTAG215 de 496 octets, alors qu'un NTAG213 n'en a que 144. La bobine est tout de même liée au tag et sera donc reconnue, mais le tag ne contient aucune donnée." },  // STR_TW_ERR_SPACE
  { "Fehlgeschlagen - Tag still halten", "Failed - keep the tag still",
    "Échec - gardez le tag immobile" },  // STR_TW_ERR_WRITE
  { "Tag beim Trigger beschreiben", "Write tag on trigger",
    "Écrire le tag au déclenchement" },  // STR_FLM_REMOTE_WRITE
  { "Nur wenn nicht gefragt wird", "Only when not asking",
    "Seulement si rien n'est demandé" },  // STR_FLM_REMOTE_WRITE_SUB
  { "Wenn der Filament-Manager einen Schreibvorgang auslöst, fragt die Waage nach - dort kannst du zwischen Beschreiben und nur Verknüpfen wählen. Ohne Nachfrage (Verknüpfen ohne Rückfrage) gibt es diese Wahl nicht. Dieser Schalter entscheidet dann, ob ein beschreibbarer NTAG die Spulendaten bekommt oder nur verknüpft wird. Bambu-Tags sind nur lesbar und werden immer nur verknüpft.",
    "When the filament manager triggers a write, the scale writes the tag and links it in one step. With the prompt turned off (link without asking) that happens without any question at all. Off, the trigger only links, exactly as it did before. Bambu tags are read-only and are always only linked.",
    "Quand FilaMan demande l'écriture d'un tag, la balance écrit le tag et le lie à la bobine en une seule étape. Si l'option Lier sans demander est activée, tout se fait sans aucune question. Si ce réglage est désactivé, la demande ne fait que lier le tag, sans rien y écrire. Les tags Bambu sont en lecture seule et sont toujours seulement liés." },  // STR_FLM_REMOTE_WRITE_INFO
  { "%s passt nicht: %u Byte nötig, %u vorhanden. Dafür braucht es einen NTAG215.",
    "%s does not fit: %u bytes needed, %u available. That wants an NTAG215.",
    "%s ne convient pas : %u octets nécessaires, %u disponibles. Il faut un NTAG215." },  // STR_W_TAG_TOOSMALL

  // Results of a write or an erase
  { "Tag nicht beschrieben", "Tag not written", "Tag non écrit" },  // STR_TW_FAILED
  { "Die Spulendaten stehen jetzt im Format OpenSpool auf dem Tag.",
    "The spool data is now on the tag, as OpenSpool.",
    "Les données de la bobine sont maintenant sur le tag, au format OpenSpool." },  // STR_TW_OK_INFO
  { "Tag auch löschen?", "Erase the tag too?", "Effacer aussi le tag ?" },  // STR_TW_ERASE_ASK_TITLE
  { "Die Verknüpfung ist gelöst. Der Tag trägt die Spulendaten aber weiter.",
    "The link is gone. The tag still carries the spool data though.",
    "La liaison est supprimée, mais le tag contient encore les données de la bobine." },  // STR_TW_ERASE_ASK_HINT
  { "Löschen",      "Erase",      "Effacer" },  // STR_TW_BTN_ERASE
  { "Behalten",     "Keep",       "Conserver" },  // STR_TW_BTN_KEEP
  { "Tag gelöscht", "Tag erased", "Tag effacé" },  // STR_TW_ERASED
  { "Der Tag ist leer und kann neu beschrieben werden.",
    "The tag is empty and ready to be written again.",
    "Le tag est vide et prêt à être réécrit." },  // STR_TW_ERASED_INFO
  { "Tag nicht gelöscht", "Tag not erased", "Tag non effacé" },  // STR_TW_ERASE_FAILED
  { "OK",                 "OK",             "OK" },  // STR_BTN_OK

  // Web access. The first line is an LVGL label and stays one row wide; the
  // other two are the web footer and carry HTML.
  { "Weboberfläche dafür freigeschaltet",
    "Web interface switched on for this",
    "Interface web activée pour cette action" },  // STR_WEB_GATE_OPENED
  { "sind am Gerät ausgeschaltet und werden nicht ausgeliefert. Einschalten unter",
    "are switched off on the device and are not being served. Switch them on under",
    "sont désactivés sur l'appareil et ne sont pas servis. Activez-les dans" },  // STR_W_FOOT_GATE_OFF
  { "Welche Bereiche ausgeliefert werden, entscheidet das Gerät unter",
    "Which sections are served is decided on the device under",
    "Les sections proposées se choisissent sur l'appareil, dans" },  // STR_W_FOOT_GATE_ALL

  // Weight popup, in place of the archive button when the spool is archived.
  // The %.0f is the net weight on the pad: the button names the number it is
  // about to write, so nothing is decided out of sight.
  { LV_SYMBOL_REFRESH " Reaktivieren\nRest wird %.0f g",
    LV_SYMBOL_REFRESH " Reactivate\nremaining set to %.0f g",
    LV_SYMBOL_REFRESH " Réactiver\nrestant mis à %.0f g" },  // STR_BTN_REACTIVATE

  // Backend options, mirrored in the browser
  { "Wird geladen ...",
    "Loading ...",
    "Chargement ..." },  // STR_W_LOADING
  { "am Gerät",
    "on the device",
    "sur l'appareil" },  // STR_W_ON_DEVICE
  { "Dieses Backend hat keine weiteren Optionen.",
    "This backend has no further options.",
    "Ce backend n'a pas d'autre option." },  // STR_W_NO_OPTIONS
  { "Filamentverwaltung",
    "Filament manager",
    "Gestion du filament" },  // STR_W_C_BACKEND
  { "Adresse, Zugangsdaten und Optionen gehören jeweils zu einer Verwaltung und bleiben beim Wechsel erhalten.",
    "Address, credentials and options belong to one manager each and survive a switch.",
    "L'adresse, les identifiants et les options sont propres à chaque gestionnaire, et restent enregistrés quand vous passez de l'un à l'autre." },  // STR_W_BACKEND_NOTE
  // %s is the name of the backend being switched to.
  { "Auf %s umschalten? Die Waage spricht danach mit einem anderen Bestand.",
    "Switch to %s? The scale will talk to a different inventory afterwards.",
    "Basculer vers %s ? La balance dialoguera ensuite avec un autre inventaire." },  // STR_W_BACKEND_ASK
  { "Panel",
    "Panel",
    "Écran" },  // STR_W_C_PANEL
  { "Beim Auflegen aufwachen",
    "Wake when a spool is put down",
    "Réveiller l'écran à la pose d'une bobine" },  // STR_W_WAKE
  // Only the half a reader can act on. Why it is on by default is already in
  // the label; what belongs here is when to turn it off.
  { "Ausschalten, wenn die Waage neben etwas steht, das sie anstößt.",
    "Turn it off for a scale that shares a bench with something that knocks it.",
    "À désactiver si la balance est posée près de quelque chose qui la bouscule et risque de rallumer l'écran." },  // STR_W_WAKE_HINT

  // Resetting the calibration, and the two refusals that keep a bad one from
  // being stored in the first place.
  { "Kalibrierung und Tara zurücksetzen?",
    "Reset calibration and tare?",
    "Réinitialiser l'étalonnage et la tare ?" },  // STR_CAL_RESET_CONFIRM
  { LV_SYMBOL_OK "  Kalibrierung zurückgesetzt",
    LV_SYMBOL_OK "  Calibration reset",
    LV_SYMBOL_OK "  Étalonnage réinitialisé" },  // STR_CAL_RESET_DONE
  { "Referenz: 10 - 20000 g", "Reference: 10 - 20000 g", "Référence : 10 - 20000 g" },  // STR_CAL_RANGE_ERR
  { LV_SYMBOL_WARNING "  Messwert unplausibel, nicht gespeichert",
    LV_SYMBOL_WARNING "  Reading implausible, not saved",
    LV_SYMBOL_WARNING "  Mesure invraisemblable, non enregistrée" },  // STR_CAL_IMPLAUSIBLE
  { "I2C-Bus",          "I2C bus",    "Bus I2C" },  // STR_W_R_I2C
  { "Bus neu abfragen", "Rescan bus", "Réinterroger le bus" },  // STR_W_RESCAN

  // ---- Writing a tag after a link ----
  { "Tag nach Verlinken beschreiben",
    "Write tag after linking",
    "Écrire le tag après la liaison" },  // STR_TW_OPT_ASK
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
    "Ce qui arrive au tag une fois la bobine liée. L'écriture remplace tout son contenu : ce qui s'y trouve actuellement est perdu.\n\nDésactivé : seul l'UID du tag est associé à la bobine, le tag lui-même reste intact. L'écriture reste possible depuis la page Tags de l'interface web, qui montre à l'avance ce qui sera écrit.\n\nDemander : la balance demande à chaque fois.\n\nÉcrire à chaque fois : aucune question, seul le résultat est affiché.\n\nSeul un NTAG assez grand est écrit. Un NTAG213 de 144 octets est trop petit pour OpenSpool et FilaMan ; un NTAG215 ou un NTAG216 suffit. Les tags Bambu ne peuvent pas être écrits." },  // STR_TW_OPT_ASK_INFO
  { "Format", "Format", "Format" },  // STR_TW_OPT_FMT
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
    "Le format décide qui pourra lire le tag.\n\nOpenSpool est un enregistrement NDEF contenant le matériau, la couleur, la marque, les températures et l'ID de la bobine ; FilaMan et les lecteurs OpenSpool savent le lire.\n\nFilaMan est le même enregistrement, sous le nom de protocole qu'attend une installation FilaMan.\n\nAnycubic ACE n'écrit aucun enregistrement, mais des pages brutes contenant la référence article, la marque, le matériau, la couleur, les températures de buse et de plateau, le diamètre, la longueur et le poids. L'ACE les lit directement." },  // STR_TW_OPT_FMT_INFO
  { "OpenSpool",          "OpenSpool",     "OpenSpool" },  // STR_TW_FMT_OPENSPOOL
  { "FilaMan",            "FilaMan",       "FilaMan" },  // STR_TW_FMT_FILAMAN
  { "Anycubic ACE",       "Anycubic ACE",  "Anycubic ACE" },  // STR_TW_FMT_ACE
  { "Tag beschreiben",    "Writing tags",  "Écriture des tags" },  // STR_W_C_TAGOPTS
  { "Nach dem Verlinken", "After linking", "Après la liaison" },  // STR_W_TAGOPT_ASK
  { "Format",             "Format",        "Format" },  // STR_W_TAGOPT_FMT
  { "Gilt für das, was die Waage nach einem Verlinken selbst tut. "
    "Das Schreiben auf dieser Seite hat seine eigene Formatauswahl.",
    "Applies to what the scale does on its own after a link. Writing from this "
    "page has its own format selector.",
    "Ces réglages concernent ce que la balance fait d'elle-même après avoir lié un tag à une bobine. L'écriture lancée depuis cette page a son propre choix de format, plus haut." },  // STR_W_TAGOPT_NOTE
  { "Speichern",    "Download",   "Enregistrer" },  // STR_W_LOG_DOWNLOAD
  { "Kal. löschen", "Reset cal.", "RAZ étal." },  // STR_BTN_CAL_RESET_SHORT
  { "Kein Material passte - Filter aufgehoben",
    "No material matched - filter dropped",
    "Aucun matériau ne correspondait - filtre levé" },  // STR_LIST_MAT_IGNORED
  { "Bei Abweichung fragen", "Ask on a mismatch", "Demander en cas d'écart" },  // STR_TW_OPT_MISM
  { "Wenn der Tag nicht zur Spule passt",
    "When the tag disagrees with the spool",
    "Si le tag ne correspond pas à la bobine" },  // STR_TW_OPT_MISM_SUB
  { "Traegt der Tag ein anderes Material, eine andere Marke oder eine deutlich "
    "andere Farbe als die verknuepfte Spule, bietet die Waage an, ihn neu zu "
    "beschreiben. Verglichen wird nur der Inhalt, nicht das Format. Aus "
    "bleibt der Tag unangetastet.",
    "If the tag carries a different material, brand or a clearly different "
    "colour than the spool it is bound to, the scale offers to write it again. "
    "Only the contents are compared, not the format. Off leaves the tag "
    "untouched.",
    "Si le tag indique un autre matériau, une autre marque ou une couleur nettement différente de celle de la bobine liée, la balance propose de le réécrire. Seul le contenu est comparé, pas le format. Désactivé : le tag reste intact." },  // STR_TW_OPT_MISM_INFO
  { "Tag weicht ab",   "Tag disagrees", "Le tag ne correspond pas" },  // STR_TW_MISM_TITLE
  { "%s",              "%s",            "%s" },  // STR_TW_MISM_HINT
  { "Neu beschreiben", "Write again",   "Réécrire" },  // STR_TW_BTN_REWRITE
  { "Tag",             "Tag",           "Tag" },  // STR_TW_MISM_TAG
  { "Server",          "Server",        "Serveur" },  // STR_TW_MISM_SERVER
  { "An der Waage fragen, wenn der Tag nicht zur Spule passt",
    "Ask at the scale when the tag disagrees with the spool",
    "Demander sur la balance quand le tag ne correspond pas à la bobine" },  // STR_W_TAGOPT_MISM
  { "Spule %d wird geschrieben...", "Writing spool %d...", "Écriture de la bobine %d..." },  // STR_W_TW_WRITING
  { "Tag wird geleert...",          "Erasing the tag...",  "Effacement du tag..." },  // STR_W_TW_ERASING
  { "Spule %d (%s) als %s geschrieben",
    "Wrote spool %d (%s) as %s",
    "Tag écrit pour la bobine %d (%s) au format %s" },  // STR_W_TW_WROTE
  { ", verknüpft",      ", linked to the spool", ", lié à la bobine" },  // STR_W_TW_LINKED
  { ", verknüpft (%s)", ", linked (%s)",         ", liaison établie (%s)" },  // STR_W_TW_LINKED_NOTE
  { ", aber das Verknüpfen schlug fehl (HTTP %d)",
    ", but linking failed (HTTP %d)",
    ", mais la liaison a échoué (HTTP %d)" },  // STR_W_TW_LINK_FAIL
  { "Tag geleert", "Tag erased", "Tag effacé" },  // STR_W_TW_ERASED
  { "Löschen fehlgeschlagen - Tag ruhig halten",
    "Erase failed - keep the tag still",
    "Échec de l'effacement - gardez le tag immobile" },  // STR_W_TW_ERASE_FAIL
  { "MIFARE Classic, nur lesbar", "MIFARE Classic, read-only",
    "MIFARE Classic, lecture seule" },  // STR_W_TAG_KIND_MIFARE
  { "NTAG, beschreibbar",         "NTAG, writable",            "NTAG, inscriptible" },  // STR_W_TAG_KIND_NTAG
  { ", %u Byte",                  ", %u bytes",                ", %u octets" },  // STR_W_TAG_KIND_BYTES
  { "Gebunden über: %s",          "Bound through: %s",         "Liée via : %s" },  // STR_UNLINK_SOURCES
  { "Aus",                        "Off",                       "Désactivé" },  // STR_TW_MODE_OFF
  { "Fragen",                     "Ask",                       "Demander" },  // STR_TW_MODE_ASK
  { "Immer schreiben",            "Write every time",          "Écrire à chaque fois" },  // STR_TW_MODE_ALWAYS

  // ---- Hardware self diagnosis -----------------------------------------
  { "  -  antippen", "  -  tap for help", "  -  touchez ici" },  // STR_DIAG_TAP
  { "Später",        "Later",             "Plus tard" },  // STR_DIAG_BTN_LATER
  { "Erneut prüfen", "Check again",       "Vérifier à nouveau" },  // STR_DIAG_BTN_RECHECK

  { "Kein Modul am I2C-Bus", "Nothing on the I2C bus", "Rien sur le bus I2C" },  // STR_DIAG_BUS_EMPTY_BANNER
  { "Kein Modul am I2C-Bus", "Nothing on the I2C bus", "Rien sur le bus I2C" },  // STR_DIAG_BUS_EMPTY_TITLE
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
    "Ni le lecteur NFC ni le convertisseur de la balance (NAU7802) ne répondent.\n\nDans la prise I/O à 8 broches, le câble à 7 broches doit être aligné sur le côté gauche. Décalé d'une seule broche, il n'alimente plus aucun des deux modules.\n\nVérifiez la broche 1 (5V, rouge), la broche 2 (GND, noir), la broche 3 (SDA, jaune) et la broche 4 (SCL, vert)." },  // STR_DIAG_BUS_EMPTY_TEXT

  { "Waagen-ADC fehlt (NAU7802)", "Scale ADC missing (NAU7802)",
    "Convertisseur absent (NAU7802)" },  // STR_DIAG_NAU_MISSING_BANNER
  { "Waagen-ADC fehlt", "Scale ADC missing",
    "Convertisseur de la balance absent" },  // STR_DIAG_NAU_MISSING_TITLE
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
    "Le NAU7802 ne répond pas à l'adresse 0x2A. Le lecteur NFC, lui, répond : les fils SDA et SCL sont donc bons en principe.\n\nVérifiez les fils VIN, GND, SDA et SCL sur le NAU7802.\n\nSur les câbles STEMMA QT tout faits d'autres fabricants, l'ordre des broches diffère souvent de celui du câble WT32.\n\nSi cet appareil est volontairement monté sans balance, désactivez « Balance présente » dans Réglages > Balance : ce message disparaîtra." },  // STR_DIAG_NAU_MISSING_TEXT

  { "NFC-Reader fehlt (PN532)", "NFC reader missing (PN532)",
    "Lecteur NFC absent (PN532)" },  // STR_DIAG_PN532_MISSING_BANNER
  { "NFC-Reader fehlt",         "NFC reader missing",         "Lecteur NFC absent" },  // STR_DIAG_PN532_MISSING_TITLE
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
    "Le PN532 ne répond pas à l'adresse 0x24. Le convertisseur de la balance, lui, répond : les fils SDA et SCL sont donc bons en principe.\n\nVérifiez d'abord les deux interrupteurs DIP du module : pour l'I2C, SW1 doit être sur ON et SW2 sur OFF. En position HSU ou SPI, la puce ne répond pas du tout sur le bus I2C - c'est exactement le symptôme observé.\n\nSinon, le PN532 doit recevoir le 5V de la broche 1 du câble I/O. Ne le branchez pas à la suite du NAU7802, par le connecteur STEMMA QT de celui-ci : ce connecteur ne fournit que du 3,3V." },  // STR_DIAG_PN532_MISSING_TEXT

  { "NFC-Reader antwortet nicht", "NFC reader does not answer",
    "Le lecteur NFC ne répond pas" },  // STR_DIAG_PN532_MUTE_BANNER
  { "NFC-Reader meldet sich nicht", "NFC reader stays silent",
    "Le lecteur NFC reste muet" },  // STR_DIAG_PN532_MUTE_TITLE
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
    "Le PN532 se signale à l'adresse 0x24, mais ne répond à aucune commande. Il est donc bien réglé en I2C - sinon il ne se signalerait pas du tout - et les fils SDA et SCL sont bons eux aussi.\n\nVérifiez d'abord les deux interrupteurs DIP : pour l'I2C, SW1 doit être sur ON et SW2 sur OFF. Un interrupteur resté entre deux positions est la cause la plus fréquente.\n\nVérifiez ensuite le 5V sur la broche 1. Avec une tension trop faible, la puce se signale sur le bus sans pouvoir fonctionner.\n\nIci, la balance ne peut pas réinitialiser la puce par un signal : le fil orange RST est relié à une sortie du module, et non à son entrée de réinitialisation. Débrancher puis rebrancher est la seule réinitialisation matérielle possible." },  // STR_DIAG_PN532_MUTE_TEXT

  { "Waage nicht kalibriert", "Scale not calibrated", "Balance non étalonnée" },  // STR_DIAG_UNCAL_BANNER
  { "Waage nicht kalibriert", "Scale not calibrated", "Balance non étalonnée" },  // STR_DIAG_UNCAL_TITLE
  { "Der angezeigte Wert ist der Rohwert des ADC, nicht Gramm. Deshalb steht "
    "dort eine sechsstellige Zahl, die von selbst um Hunderte springt.\n\n"
    "Das ist kein Defekt und kein Verkabelungsfehler. Die Waage weiß nur noch "
    "nicht, wie viele Messschritte ein Gramm sind.\n\n"
    "Lege ein bekanntes Gewicht auf und kalibriere sie.",
    "The value on screen is the raw ADC reading, not grams. That is why it is "
    "a six digit number that jumps by hundreds on its own.\n\n"
    "This is neither a defect nor a wiring mistake. The scale simply does not "
    "know yet how many counts make a gram.\n\n"
    "Place a known weight on it and calibrate.",
    "La valeur affichée est la mesure brute, pas un poids en grammes. C'est pourquoi vous voyez un nombre à six chiffres qui varie tout seul de plusieurs centaines.\n\nCe n'est ni une panne ni une erreur de câblage. La balance ne sait simplement pas encore à combien d'unités brutes correspond un gramme.\n\nPosez un poids connu sur le plateau et étalonnez la balance." },  // STR_DIAG_UNCAL_TEXT

  { "Wägezelle verpolt (A+/A-)", "Load cell reversed (A+/A-)",
    "Capteur de pesée inversé (A+/A-)" },  // STR_DIAG_INVERTED_BANNER
  { "Wägezelle verpolt", "Load cell reversed",
    "Capteur de pesée inversé" },  // STR_DIAG_INVERTED_TITLE
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
    "À vide, la balance affiche une valeur très négative et n'a mesuré aucun poids positif depuis le démarrage. Poser un objet la fait baisser au lieu de l'augmenter.\n\nInversez les deux fils de signal sur le NAU7802 : A+ (blanc) et A- (vert).\n\nRefaites ensuite la tare et l'étalonnage." },  // STR_DIAG_INVERTED_TEXT

  { "Wägezelle unruhig", "Load cell unstable", "Capteur de pesée instable" },  // STR_DIAG_NOISY_BANNER
  { "Wägezelle unruhig", "Load cell unstable", "Capteur de pesée instable" },  // STR_DIAG_NOISY_TITLE
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
    "La mesure varie en permanence de plus de %d g alors que rien ne bouge sur le plateau.\n\nC'est typique d'un fil mal fixé sur le NAU7802. Vérifiez E+ (rouge), E- (noir), A+ (blanc) et A- (vert), à la recherche d'une soudure froide.\n\nVérifiez aussi qu'aucun câble n'appuie contre le plateau de pesée." },  // STR_DIAG_NOISY_TEXT

  { "So kalibrierst du", "How to calibrate", "Comment étalonner" },  // STR_CAL_HELP_TITLE
  { "1. Plattform leer räumen und TARE drücken. Die Anzeige muss auf 0 gehen.\n\n"
    "2. Ein Gewicht auflegen, das du genau kennst. Ideal sind etwa 1000 g - "
    "eine volle Spule, auf einer Küchenwaage nachgewogen, reicht völlig.\n\n"
    "3. Dieses Gewicht in Gramm eintippen und auf Berechnen drücken.\n\n"
    "Je genauer das Referenzgewicht, desto genauer misst die Waage danach.",
    "1. Clear the platform and press TARE. The reading has to go to 0.\n\n"
    "2. Place a weight you know exactly. Around 1000 g is ideal - a full spool "
    "checked on a kitchen scale is plenty.\n\n"
    "3. Type that weight in grams and press Calculate.\n\n"
    "The more precise the reference weight, the more accurate the scale is "
    "afterwards.",
    "1. Videz le plateau et appuyez sur TARE. L'affichage doit passer à 0.\n\n2. Posez un poids que vous connaissez exactement. L'idéal est un poids d'environ 1000 g - une bobine pleine, pesée sur une balance de cuisine, suffit amplement.\n\n3. Saisissez ce poids en grammes et appuyez sur Calculer.\n\nPlus le poids de référence est précis, plus les mesures de la balance seront précises ensuite." },  // STR_CAL_HELP_TEXT

  { "Diagnose",    "Diagnosis",     "Diagnostic" },  // STR_W_R_DIAG
  { "ohne Befund", "nothing found", "rien à signaler" },  // STR_W_S_DIAG_OK

  // ---- PN532 reset line, the optional hardware modification ----
  { "Hardware-Umbau möglich", "A hardware change is available",
    "Modification matérielle possible" },  // STR_NFCRST_HINT_TITLE
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
    "Le lecteur NFC de cette balance a déjà dû être redémarré au moins une fois.\n\nUne modification facultative y remédie : déplacer le fil orange RST sur RSTPDN. La balance pourra alors vraiment réinitialiser le lecteur.\n\nLa marche à suivre se trouve dans la documentation, section Wiring (câblage). Contrôlez ensuite le résultat dans Système > Vérifier la réinit. NFC. Si vous ne faites pas cette modification, rien ne sera endommagé." },  // STR_NFCRST_HINT_TEXT
  { "Später",              "Later",             "Plus tard" },  // STR_NFCRST_LATER
  { "Nicht mehr anzeigen", "Do not show again", "Ne plus afficher" },  // STR_NFCRST_NEVER

  { "NFC-Reset prüfen",       "Check NFC reset",       "Vérifier la réinit. NFC" },  // STR_NFCRST_ROW
  { "Nach dem Umlöten",       "After the rewiring",    "Après la modification du câblage" },  // STR_NFCRST_ROW_SUB
  { "Leitung geprüft, aktiv", "Line verified, in use", "Liaison vérifiée, active" },  // STR_NFCRST_ROW_DONE
  { "Reset-Leitung sitzt", "Reset line is there",
    "Liaison de réinitialisation présente" },  // STR_NFCRST_OK_TITLE
  { "Der Leser hat auf die Leitung reagiert. Ab dem nächsten Start benutzt "
    "die Waage den Hardware-Reset.",
    "The reader responded to the line. From the next start the scale uses the "
    "hardware reset.",
    "Le lecteur a réagi à la liaison. Dès le prochain démarrage, la balance utilisera la réinitialisation matérielle." },  // STR_NFCRST_OK_TEXT
  { "Keine Wirkung", "No effect", "Aucun effet" },  // STR_NFCRST_FAIL_TITLE
  { "Der Leser hat nichts gemerkt. Der orange Draht liegt noch auf dem alten "
    "Pad, oder die Lötstelle hat keinen Kontakt.\n\n"
    "Es ändert sich nichts, die Waage arbeitet weiter wie bisher.",
    "The reader did not notice. The orange wire is still on the old pad, or "
    "the joint is not making contact.\n\n"
    "Nothing changes, the scale carries on as before.",
    "Le lecteur n'a pas réagi au test de réinitialisation. Soit le fil orange est encore sur l'ancienne pastille, soit la soudure ne fait pas contact.\n\nRien n'est modifié : la balance continue de fonctionner comme avant." },  // STR_NFCRST_FAIL_TEXT

  // ── Hardware UID into extra.rfid_tag ──
  { "Chip-UID mitschreiben",  "Also write the chip UID", "Écrire aussi l'UID de la puce" },  // STR_HW_UID_WRITE
  { "Zusätzlich in rfid_tag", "Into rfid_tag as well",   "Également dans rfid_tag" },  // STR_HW_UID_WRITE_SUB
  { "An: die Hardware-UID des Chips, der gerade auf dem Leser liegt, kommt "
    "zusätzlich in das Extra-Feld rfid_tag, als kommagetrennte Liste. Die "
    "Bindung selbst bleibt unverändert in dem Feld, das oben gewählt ist.\n\n"
    "Happy Hare an einem Voron liest ausschliesslich rfid_tag, und die Leser "
    "an den Gates sehen nur die Hardware-UID des Chips, nie die tray_uuid "
    "einer Bambu-Spule. Ohne dieses Feld findet der Drucker die Spule nicht, "
    "die auf der Waage längst erkannt wird.\n\n"
    "Eine Bambu-Spule trägt zwei Chips, also zwei UIDs. Die Liste wächst von "
    "selbst: einmal jede Seite auflegen, danach antwortet die Spule an beiden "
    "Gates.\n\n"
    "Die Waage schreibt dabei in jede Spule, die sie erkennt, nicht erst beim "
    "Verknüpfen. Steht die UID schon drin, geht keine Anfrage mehr raus. Das "
    "Feld legt Happy Hare selbst an.",
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
    "link is made. Once the UID is in there, no request goes out again. Happy "
    "Hare creates the field itself.",
    "Activé : l'UID matériel de la puce posée sur le lecteur est aussi ajouté au champ supplémentaire rfid_tag, dans une liste séparée par des virgules. La liaison elle-même reste inchangée, dans le champ choisi plus haut.\n\nSur une Voron, Happy Hare ne lit que rfid_tag, et les lecteurs placés à ses entrées (gates) ne voient que l'UID matériel de la puce, jamais la tray_uuid d'une bobine Bambu. Sans ce champ, l'imprimante ne trouve pas une bobine que la balance reconnaît pourtant très bien.\n\nUne bobine Bambu porte deux puces, donc deux UID. La liste se complète toute seule : posez une fois chaque côté de la bobine sur le lecteur, et elle sera reconnue aux deux entrées.\n\nLa balance renseigne ce champ pour chaque bobine qu'elle reconnaît, pas seulement lors d'une liaison. Si l'UID y figure déjà, elle n'envoie plus aucune requête. Le champ est créé par Happy Hare lui-même." },  // STR_HW_UID_WRITE_INFO

  // ── A link that could not use the selected source ──
  { "Tag-Quelle nicht verfügbar", "Tag source unavailable", "Source de tag indisponible" },  // STR_TF_NOREL_TITLE
  { "Dieser Spoolman hat noch keine eigene Tag-Relation - die gibt es erst ab "
    "v0.27. Als Quelle sind aber die nativen Tags gewählt.\n\n"
    "Der Tag wurde deshalb in das Extra-Feld tag geschrieben, das jeder "
    "Spoolman hat. Die Spule wird damit gefunden, nur nicht auf dem "
    "schnellsten Weg.\n\n"
    "Dauerhaft besser: unter Einstellungen die Tag-Quelle auf card_uids "
    "stellen. Das Feld hält auch mehrere UIDs je Spule, also auch einen "
    "zweiten Tag. Sobald der Server auf v0.27 steht, zieht die Waage die "
    "Bindung beim nächsten Verknüpfen von selbst in die Relation um.",
    "This Spoolman has no tag relation of its own yet - that arrives in v0.27. "
    "The selected source is native tags all the same.\n\n"
    "The tag went into the extra field tag instead, which every Spoolman has. "
    "The spool is found by it, just not by the fastest route.\n\n"
    "Better for good: set the tag source to card_uids under Settings. That "
    "field also holds several UIDs per spool, so a second tag fits too. Once "
    "the server is on v0.27 the scale moves the binding into the relation by "
    "itself, on the next link.",
    "Ce serveur Spoolman ne gère pas encore les tags nativement - cette fonction n'arrive qu'en v0.27. La source choisie est pourtant « Spoolman NFC (natif) ».\n\nLe tag a donc été enregistré dans le champ supplémentaire extra.tag, que tout Spoolman possède. La bobine est bien retrouvée grâce à lui, mais pas par le chemin le plus rapide.\n\nSolution durable : dans les réglages, choisissez extra.card_uids comme champ du tag. Ce champ accepte plusieurs UID par bobine, donc aussi un second tag. Dès que le serveur sera en v0.27, la balance déplacera d'elle-même le tag vers la gestion native, lors de la prochaine liaison." },  // STR_TF_NOREL_TEXT

  // ── The tag on the other flange ──
  { "Zweites Tag abfragen", "Ask for a second tag", "Demander un second tag" },  // STR_TAG2_ASK
  { "Nach dem Verknüpfen",  "Right after a link",   "Juste après une liaison" },  // STR_TAG2_ASK_SUB
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
    "Activé : après chaque liaison réussie, la balance demande un second tag. Retournez la bobine, posez le tag sur le lecteur, c'est fait - il est lié à la même bobine que le premier.\n\nLa demande d'origine était un second lecteur, un de chaque côté du boîtier. Le matériel ne le permet pas : c'est donc une étape à l'écran qui remplace ce composant.\n\nSur une bobine Bambu, les deux puces portent la même tray_uuid : l'UID de la seconde puce finirait donc par être ajouté de toute façon. La question indique seulement le bon moment pour le faire. Deux NTAG, en revanche, n'ont rien en commun : sans cette question, il faudrait rechercher la bobine à la main une seconde fois.\n\nCette ligne n'apparaît que si la source choisie peut contenir plus d'un tag. L'écriture des données sur le second tag reste décidée par le réglage « Écrire le tag après la liaison »." },  // STR_TAG2_ASK_INFO
  { "Zweites Tag", "Second tag", "Second tag" },  // STR_TAG2_TITLE
  { "Spule umdrehen und das zweite Tag auflegen",
    "Turn the spool over and place the second tag",
    "Retournez la bobine et posez le second tag" },  // STR_TAG2_PROMPT
  { "Schließt in %d s",      "Closes in %d s",    "Se ferme dans %d s" },  // STR_TAG2_CLOSES_IN
  { "Fertig",                "Done",              "Terminer" },  // STR_TAG2_BTN_DONE
  { "Zweites Tag verknüpft", "Second tag linked", "Second tag lié" },  // STR_TAG2_LINKED

  // ── A device built without a load cell ──
  { "Keine Waage angeschlossen", "No scale connected", "Aucune balance connectée" },  // STR_NO_SCALE
  { "Waage vorhanden",           "Scale fitted",       "Balance présente" },  // STR_SCALE_FITTED
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
    "Activé : l'appareil a un capteur de pesée et fonctionne exactement comme avant.\n\nDésactivé : toute la partie pesée disparaît. Le NAU7802 n'est même plus recherché au démarrage, l'écran principal affiche un message à la place des poids et plus rien là où se trouvait TARE, le bouton « Envoyer le poids » devient le bouton « Emplacement », et Étalonnage et Poids du sachet disparaissent de ce menu.\n\nPrévu pour un appareil composé seulement d'un écran et d'un lecteur : poser un tag, voir la bobine, lui attribuer un emplacement et une imprimante. Sans ce réglage, un tel appareil signale en permanence une panne qu'il n'a pas.\n\nLe changement nécessite un redémarrage." },  // STR_SCALE_FITTED_INFO
  { "Ohne Waage | Mehr", "No scale | More", "Sans balance | Plus" },  // STR_TILE_SCALE_SUB_OFF
  { "Waage vorhanden",   "Scale fitted",    "Balance présente" },  // STR_W_SCALE_FITTED
  { "Aus, wenn das Gerät nur aus Display und Leser besteht. Braucht einen "
    "Neustart.",
    "Off if the device is display and reader only. Needs a restart.",
    "À désactiver si l'appareil se limite à un écran et un lecteur. Nécessite un redémarrage." },  // STR_W_SCALE_FITTED_HINT
  { "abgeschaltet", "switched off", "désactivée" },  // STR_W_S_SCALE_OFF

  { "Passwort", "Password", "Mot de passe" },  // STR_WEB_PASS
  { "Gesetzt - der Browser fragt danach",
    "Set - the browser asks for it",
    "Défini - le navigateur le demande" },  // STR_WEB_PASS_SET
  { "Nicht gesetzt", "Not set", "Non défini" },  // STR_WEB_PASS_UNSET
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
    "Protège les sections Réglages et Maintenance de l'interface web : backend, réglages, tags, journaux et firmware. Sans mot de passe, tout appareil du réseau peut utiliser ces sections dès qu'elles sont activées - y compris installer un firmware.\n\n4 à 8 chiffres. Le navigateur vous le demandera ; le nom d'utilisateur est ignoré. Validez sans rien saisir pour supprimer le mot de passe." },  // STR_WEB_PASS_INFO
  { "Web-Passwort", "Web password", "Mot de passe web" },  // STR_WEB_PASS_TITLE
  { "4 bis 8 Ziffern. Leer speichern entfernt das Passwort.",
    "4 to 8 digits. Save empty to remove the password.",
    "4 à 8 chiffres. Validez sans rien saisir pour supprimer le mot de passe." },  // STR_WEB_PASS_HINT
  { "Passwort",      "Password", "Mot de passe" },  // STR_W_R_PASSWORD
  { "gesetzt",       "set",      "défini" },  // STR_W_S_SET
  { "nicht gesetzt", "not set",  "non défini" },  // STR_W_S_NOTSET
  { "Ohne Passwort kann jedes Gerät im Netz die eingeschalteten Bereiche nutzen, "
    "Firmware flashen eingeschlossen. Setzen am Gerät unter",
    "Without a password any device on the network can use the sections that "
    "are on, firmware upload included. Set one on the device under",
    "Sans mot de passe, tout appareil du réseau peut utiliser les sections activées, y compris installer un firmware. Définissez-en un sur l'écran de la balance, dans" },  // STR_W_PASS_NOTE
  { "Passwort nötig: beliebiger Benutzername, das Web-Passwort der Waage.",
    "Password required: any user name, the scale's web password.",
    "Mot de passe requis : n'importe quel nom d'utilisateur, et le mot de passe web de la balance." },  // STR_W_AUTH_NEEDED
  { "Diese Adresse gehört nicht zur Waage. Bitte über die IP-Adresse oder den "
    "Gerätenamen aufrufen.",
    "This address does not belong to the scale. Open it by IP address or by "
    "its device name.",
    "Cette adresse n'appartient pas à la balance. Ouvrez-la par son adresse IP ou par son nom d'appareil." },  // STR_W_BAD_HOST
  { "Anfrage von einer fremden Seite abgelehnt.",
    "Request from a foreign page refused.",
    "Requête venue d'une page étrangère refusée." },  // STR_W_BAD_ORIGIN
  { "%d Spulen", "%d spools", "%d bobines" },  // STR_SPOOLS_COUNT
  { "Beide Tags gehören jetzt zu dieser Spule.",
    "Both tags now belong to this spool.",
    "Les deux tags appartiennent maintenant à cette bobine." },  // STR_TAG2_LINKED_INFO
  { "Zweites Tag nicht verknüpft", "Second tag not linked", "Second tag non lié" },  // STR_TAG2_FAILED
  { "Spule #%d verliert das Tag.",
    "Spool #%d loses the tag.",
    "La bobine #%d perdra ce tag." },  // STR_TAGMOVE_HINT
  { "Umhängen",                "Move",           "Déplacer" },  // STR_TAGMOVE_BTN
  { "Umhängen fehlgeschlagen", "Move failed",    "Échec du déplacement" },  // STR_TAGMOVE_FAILED
  { "Hängt an:",               "On spool:",      "Lié à :" },  // STR_TAGMOVE_FROM
  { "Umhängen zu:",            "Move to:",       "Déplacer vers :" },  // STR_TAGMOVE_TO
  { "%d Min",                  "%d min",         "%d min" },  // STR_MINUTES_FMT
  { "%d T.",                   "%d d",           "%d j" },  // STR_DAYS_ABBR_FMT
  { "%.0f g neu",              "%.0f g new",     "%.0f g neuve" },  // STR_NEW_SPOOL_WEIGHT_FMT
  { "Diff",                    "Diff",           "Écart" },  // STR_LBL_DIFF_CAP
  { "Datei wählen",            "Choose file",    "Choisir un fichier" },  // STR_W_FW_CHOOSE
  { "Keine Datei gewählt",     "No file chosen", "Aucun fichier choisi" },  // STR_W_FW_NOFILE
  { "Wartung (Firmware, Logs, Tags)",
    "Maintenance (firmware, logs, tags)",
    "Maintenance (firmware, journaux, tags)" },  // STR_W_R_MAINT_GATE
  { "AMS-Ansicht", "AMS view", "Vue AMS" },  // STR_AMS_BTN_VIEW
  { "%s -> Fenster für die Zuordnung öffnen?",
    "%s -> open the assignment window?",
    "%s -> ouvrir la fenêtre d'affectation ?" },  // STR_AMSV_WINDOW_HEAD
  { "Fenster öffnen", "Open window", "Ouvrir la fenêtre" },  // STR_AMSV_BTN_WINDOW
  { "Gespeichert - Test übersprungen, das Gerät ist beschäftigt",
    "Saved - test skipped, the device is busy",
    "Enregistré - test ignoré, l'appareil est occupé" },  // STR_W_HOST_SAVED_ONLY
  { "Bereits mit einem WLAN verbunden.",
    "Already connected to WiFi.",
    "Déjà connectée à un réseau WiFi." },  // STR_WIFI_ALREADY_CONNECTED
  { "WLAN ändern",                  "Change WiFi",              "Changer de WiFi" },  // STR_BTN_WIFI_CHANGE
  { "Per Handy einrichten",         "Set up by phone",          "Configurer par mobile" },  // STR_BTN_WIFI_PORTAL
  { "WLAN per Handy einrichten", "Set up WiFi by phone",
    "Configurer le WiFi par mobile" },  // STR_PORTAL_TITLE
  { "1. WLAN der Waage beitreten", "1. Join the scale's WiFi",
    "1. Rejoignez le WiFi affiché" },  // STR_PORTAL_STEP_JOIN
  { "2. Seite öffnen",              "2. Open the page",         "2. Ouvrez la page" },  // STR_PORTAL_STEP_OPEN
  { "WLAN: %s",                     "WiFi: %s",                 "WiFi : %s" },  // STR_PORTAL_NET_FMT
  { "Passwort: %s",                 "Password: %s",             "Mot de passe : %s" },  // STR_PORTAL_PASS_FMT
  { "Öffnet sich meist von selbst", "Usually opens by itself",
    "S'ouvre le plus souvent tout seul" },  // STR_PORTAL_OPENS_ITSELF
  { "Meldet das Handy \"kein Internet\", verbunden bleiben.",
    "If the phone reports \"no internet\", stay connected.",
    "Si le téléphone signale « pas d'Internet », restez quand même connecté." },  // STR_PORTAL_ANDROID_HINT
  { "Warte auf Eingabe am Handy...", "Waiting for the phone...",
    "Attente de la saisie sur le téléphone..." },  // STR_PORTAL_WAITING
  { "Daten empfangen, verbinde gleich...",
    "Received, connecting in a moment...",
    "Données reçues, connexion imminente..." },  // STR_PORTAL_RECEIVED
  { LV_SYMBOL_WARNING "  Das WLAN der Waage konnte nicht starten.",
    LV_SYMBOL_WARNING "  The scale's WiFi could not start.",
    LV_SYMBOL_WARNING "  Le WiFi de la balance n'a pas pu démarrer." },  // STR_PORTAL_START_FAILED
  { "Wähle das WLAN, mit dem sich die Waage verbinden soll.",
    "Choose the WiFi network the scale should join.",
    "Choisissez le réseau WiFi que la balance doit rejoindre." },  // STR_PORTAL_PAGE_INTRO
  { "Netzwerk",     "Network",       "Réseau" },  // STR_PORTAL_PAGE_NETWORK
  { "Bitte wählen", "Please choose", "Veuillez choisir" },  // STR_PORTAL_PAGE_CHOOSE
  { "Oder Namen eingeben (verstecktes Netz)",
    "Or type its name (hidden network)",
    "Ou saisissez son nom (réseau masqué)" },  // STR_PORTAL_PAGE_OTHER
  { "Passwort",  "Password", "Mot de passe" },  // STR_PORTAL_PAGE_PASS
  { "Verbinden", "Connect",  "Se connecter" },  // STR_PORTAL_PAGE_SUBMIT
  { "Die Waage verbindet sich jetzt mit %s. Das Ergebnis erscheint auf ihrem Display, dieses WLAN schaltet sich dabei ab.",
    "The scale is now connecting to %s. The result appears on its display, and this WiFi network switches off.",
    "La balance se connecte à %s. Le résultat apparaît sur son écran, et ce réseau WiFi s'éteint." },  // STR_PORTAL_PAGE_DONE
  { "Bitte ein Netzwerk wählen oder seinen Namen eingeben (höchstens 32 Zeichen).",
    "Please choose a network or type its name (32 characters at most).",
    "Veuillez choisir un réseau ou saisir son nom (32 caractères au plus)." },  // STR_PORTAL_PAGE_ERR_SSID
  { "Das Passwort hat 8 bis 64 Zeichen, bei einem offenen Netz bleibt es leer.",
    "The password has 8 to 64 characters, or stays empty for an open network.",
    "Le mot de passe compte 8 à 64 caractères, ou reste vide pour un réseau ouvert." },  // STR_PORTAL_PAGE_ERR_PASS
  { "API-Key fehlt noch", "API key still missing", "Clé d'API manquante" },  // STR_BB_KEY_MISSING
  { "API-Key abgelehnt",  "API key rejected",      "Clé d'API refusée" },  // STR_BB_KEY_REJECTED

  // AMS view: info mode and the detail card
  { "Info", "Info", "Infos" },  // STR_AMSV_INFO
  { "Fach antippen zeigt die Spule",
    "Tap a bay to see its spool",
    "Touchez un bac pour voir sa bobine" },  // STR_AMSV_INFO_HINT
  { "Der externe Halter kann nicht zugewiesen werden",
    "The external holder cannot be assigned",
    "Le support externe ne peut pas être affecté" },  // STR_AMSV_EXT_NO_PICK
  { "%s - Fach %d", "%s - bay %d", "%s - bac %d" },  // STR_AMSD_BAY
  { "Restmenge",    "Remaining",   "Reste" },  // STR_AMSD_REMAINING
  { "%s von %s",    "%s of %s",    "%s sur %s" },  // STR_AMSD_OF
  { "Kein Gewicht im Backend hinterlegt",
    "No weight stored in the backend",
    "Aucun poids enregistré dans le backend" },  // STR_AMSD_NO_WEIGHT
  { "Keine Spule im Backend verknüpft",
    "No spool linked in the backend",
    "Aucune bobine liée dans le backend" },  // STR_AMSD_NO_SPOOL
  { "Details werden geladen ...", "Loading details ...", "Chargement des détails ..." },  // STR_AMSD_LOADING
  { "Details nicht abrufbar",     "Details unavailable", "Détails indisponibles" },  // STR_AMSD_FAIL
  { "Ersatz %s",                  "Backup %s",           "Secours %s" },  // STR_AMSD_BACKUP
  { "Trocknung von heute für\ndiese Spule speichern?",
    "Record today's drying for\nthis spool?",
    "Enregistrer le séchage du jour\npour cette bobine ?" },  // STR_AMSD_DRIED_Q
  { "Wird gespeichert ...",     "Saving ...",    "Enregistrement ..." },  // STR_AMSD_SAVING
  { "Speichern fehlgeschlagen", "Saving failed", "Échec d'enregistrement" },  // STR_AMSD_WRITE_FAIL

  // The caption the main screen and More Info used to spell out as a literal.
  { "Material", "Material", "Matériau" },  // STR_LBL_MATERIAL

  // More captions that used to be literals, for the same reason.
  { "Status",             "Status",             "Statut" },  // STR_LBL_STATUS
  { "Status",             "Status",             "État" },  // STR_WIFI_ROW_STATUS
  { "Gateway",            "Gateway",            "Passerelle" },  // STR_WIFI_ROW_GATEWAY
  { "Name",               "Name",               "Nom" },  // STR_IP_BAR_NAME
  { "%s Server",          "%s Server",          "Serveur %s" },  // STR_SERVER_TITLE
  { "%s UUID",            "%s UUID",            "UUID %s" },  // STR_BACKEND_UUID
  { "Language / Sprache", "Language / Sprache", "Langue / Language / Sprache" },  // STR_LANG_SCREEN_TITLE
  { "DEL",                "DEL",                "Effacer" },  // STR_KEY_DEL

  // AMS detail card: drying for the whole unit, and the material conflict hint
  { "Trocknung von heute speichern?",
    "Record today's drying?",
    "Record today's drying?" },  // STR_AMSD_DRIED_Q_ALL
  { "Alle %d Spulen in %s", "All %d spools in %s", "All %d spools in %s" },  // STR_AMSD_DRIED_ALL
  { "Nur diese Spule",      "This spool only",     "This spool only" },  // STR_AMSD_DRIED_ONE
  { "%d Spulen werden gespeichert ...",
    "Saving %d spools ...",
    "Saving %d spools ..." },  // STR_AMSD_BATCH_RUNNING
  { "%d von %d gespeichert", "%d of %d saved", "%d of %d saved" },  // STR_AMSD_BATCH_DONE
  { "Trocknet %d min",       "Drying %d min",  "Séchage %d min" },  // STR_AMSV_DRYING_MIN
  { "Trocknet",              "Drying",         "Séchage" },  // STR_AMSV_DRYING
  { "Drucker meldet %s - Zuordnung im Backend prüfen",
    "Printer reports %s - check the assignment in the backend",
    "Printer reports %s - check the assignment in the backend" },  // STR_AMSD_TYPE_CONFLICT
};

StringID tagWriteResultString(uint8_t code) {
  switch (code) {
    case TW_OK:            return STR_TW_OK;
    case TW_ERR_NO_TAG:    return STR_TW_ERR_NO_TAG;
    case TW_ERR_NOT_NTAG:  return STR_TW_ERR_NOT_NTAG;
    case TW_ERR_BACKEND:   return STR_TW_ERR_BACKEND;
    case TW_ERR_SPACE:     return STR_TW_ERR_SPACE;
    default:               return STR_TW_ERR_WRITE;
  }
}

// Without this, a missing entry is not a compile error: every string from the
// gap onwards reads as the wrong one, in every language, and the only symptom
// is a UI that looks scrambled. That is what a merge produces when two
// branches both append here, and nothing else would catch it.
static_assert(sizeof(STRINGS) / sizeof(STRINGS[0]) == STR_COUNT,
              "STRINGS and the StringID enum are out of step");
