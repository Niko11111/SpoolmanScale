#include "creality_tag.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/aes.h"

// Both keys are the ones Creality's firmware and every community writer use
// (CFS RFID app, CFTag, K2-RFID). They are not secrets of this project.
static const uint8_t SECTOR_SECRET[16] = {
  'q','3','b','u','^','t','1','n','q','f','Z','(','p','f','$','1' };
static const uint8_t DATA_KEY[16] = {
  'H','@','C','F','k','R','n','z','@','K','A','t','B','J','p','2' };

static bool aesEcb(const uint8_t key[16], int mode, const uint8_t* in, uint8_t* out, size_t len) {
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  int rc = (mode == MBEDTLS_AES_ENCRYPT) ? mbedtls_aes_setkey_enc(&ctx, key, 128)
                                         : mbedtls_aes_setkey_dec(&ctx, key, 128);
  for (size_t off = 0; rc == 0 && off < len; off += 16) {
    rc = mbedtls_aes_crypt_ecb(&ctx, mode, in + off, out + off);
  }
  mbedtls_aes_free(&ctx);
  return rc == 0;
}

bool crealityDeriveSectorKey(const uint8_t uid4[4], uint8_t key_out[6]) {
  uint8_t in[16], enc[16];
  for (int i = 0; i < 16; i++) in[i] = uid4[i % 4];
  if (!aesEcb(SECTOR_SECRET, MBEDTLS_AES_ENCRYPT, in, enc, 16)) return false;
  memcpy(key_out, enc, 6);
  return true;
}

bool crealityDecrypt48(const uint8_t in[48], uint8_t out[48]) {
  return aesEcb(DATA_KEY, MBEDTLS_AES_DECRYPT, in, out, 48);
}

// ------------------------------------------------------------
//  Material table
//
//  Generated from DnG-Crafts/K2-RFID db/{k2,hi,k1}.json, which is Creality
//  Print's material database. The tag holds "1" + id.
// ------------------------------------------------------------
struct CrealityMaterial {
  const char* id;
  const char* brand;
  const char* name;
  const char* material;
  uint16_t    temp_min, temp_max;
};

static const CrealityMaterial MATERIALS[] = {
  {"00001", "Generic", "Generic PLA", "PLA", 190, 240},
  {"00002", "Generic", "Generic PLA-Silk", "PLA", 190, 240},
  {"00003", "Generic", "Generic PETG", "PETG", 220, 270},
  {"00004", "Generic", "Generic ABS", "ABS", 240, 280},
  {"00005", "Generic", "Generic TPU", "TPU", 210, 240},
  {"00006", "Generic", "Generic PLA-CF", "PLA-CF", 190, 240},
  {"00007", "Generic", "Generic ASA", "ASA", 240, 280},
  {"00008", "Generic", "Generic PA", "PA", 240, 260},
  {"00009", "Generic", "Generic PA-CF", "PA-CF", 260, 300},
  {"00010", "Generic", "Generic BVOH", "BVOH", 200, 220},
  {"00011", "Generic", "Generic PVA", "PVA", 215, 225},
  {"00012", "Generic", "Generic HIPS", "HIPS", 220, 250},
  {"00013", "Generic", "Generic PET-CF", "PET-CF", 280, 320},
  {"00014", "Generic", "Generic PETG-CF", "PETG-CF", 240, 260},
  {"00015", "Generic", "Generic PA6-CF", "PA6-CF", 280, 300},
  {"00016", "Generic", "Generic PAHT-CF", "PAHT-CF", 300, 320},
  {"00017", "Generic", "Generic PPS", "PPS", 320, 350},
  {"00018", "Generic", "Generic PPS-CF", "PPS-CF", 300, 350},
  {"00019", "Generic", "Generic PP", "PP", 220, 250},
  {"00020", "Generic", "Generic PET", "PET", 250, 270},
  {"00021", "Generic", "Generic PC", "PC", 250, 270},
  {"00022", "Generic", "Generic PA612-CF", "PA-CF", 270, 310},
  {"00023", "Generic", "Generic Support for PA", "PA", 260, 300},
  {"00024", "Generic", "Generic Support for PLA", "PLA", 190, 240},
  {"00025", "Generic", "Generic PA12-CF", "PA-CF", 270, 310},
  {"00026", "Generic", "Generic TPU 64D", "TPU", 210, 240},
  {"00027", "Generic", "Generic PETG-GF", "PETG-GF", 240, 280},
  {"00031", "Generic", "Generic PP-CF", "PP-CF", 220, 270},
  {"00032", "Generic", "Generic PCTG", "PCTG", 250, 270},
  {"00033", "Generic", "Generic ASA-CF", "ASA-CF", 250, 280},
  {"00034", "Generic", "Generic PA6-GF", "PA-GF", 250, 290},
  {"00035", "eSUN", "PLA-LW", "PLA", 190, 270},
  {"01001", "Creality", "Hyper PLA", "PLA", 190, 240},
  {"01002", "Creality", "Hyper L-W PLA", "PLA", 200, 270},
  {"01004", "Creality", "Hyper Stardust", "PLA", 190, 240},
  {"01601", "Creality", "Soleyin Ultra PLA", "PLA", 190, 240},
  {"02001", "Creality", "Hyper PLA-CF", "PLA-CF", 190, 240},
  {"03001", "Creality", "Hyper ABS", "ABS", 240, 280},
  {"04001", "Creality", "CR-PLA", "PLA", 190, 240},
  {"05001", "Creality", "CR-Silk", "PLA", 190, 240},
  {"06001", "Creality", "CR-PETG", "PETG", 220, 270},
  {"06002", "Creality", "Hyper PETG", "PETG", 220, 270},
  {"06003", "Creality", "Hyper PETG-CF", "PETG-CF", 240, 260},
  {"07001", "Creality", "CR-ABS", "ABS", 240, 280},
  {"07002", "Creality", "Hyper PC", "PC", 250, 270},
  {"08001", "Creality", "Ender-PLA", "PLA", 190, 240},
  {"09001", "Creality", "EN-PLA+", "PLA", 190, 240},
  {"09002", "Creality", "ENDER FAST PLA", "PLA", 190, 240},
  {"10001", "Creality", "HP-TPU", "TPU", 190, 240},
  {"11001", "Creality", "CR-Nylon", "PA", 250, 270},
  {"12002", "Creality", "Hyper PPA-CF", "PA-CF", 280, 320},
  {"12003", "Creality", "Hyper PAHT-CF", "PA-CF", 280, 320},
  {"12004", "Creality", "Hyper PA612-CF", "PA612-CF", 290, 320},
  {"12005", "Creality", "Hyper PA6-CF", "PA6-CF", 290, 320},
  {"13001", "Creality", "CR-PLA Carbon", "PLA-CF", 190, 240},
  {"14001", "Creality", "CR-PLA Matte", "PLA", 190, 240},
  {"15001", "Creality", "CR-PLA Fluo", "PLA", 190, 240},
  {"16001", "Creality", "CR-TPU", "TPU", 210, 240},
  {"17001", "Creality", "CR-Wood", "PLA", 190, 240},
  {"18001", "Creality", "HP Ultra PLA", "PLA", 190, 240},
  {"19001", "Creality", "HP-ASA", "ASA", 240, 280},
  {"29001", "Creality", "Hyper Marble", "PLA", 190, 240},
  {"E1001", "eSUN", "PLA+", "PLA", 210, 230},
  {"P1001", "Polymaker", "Panchroma PLA Satin", "PLA", 190, 230},
  {"P1002", "Polymaker", "PolySonic PLA Pro", "PLA", 190, 230},
  {"P1003", "Polymaker", "Panchroma PLA Matte", "PLA", 190, 230},
};

static const CrealityMaterial* findMaterial(const char* id5) {
  for (const CrealityMaterial& m : MATERIALS) {
    if (strcasecmp(m.id, id5) == 0) return &m;
  }
  return nullptr;
}

// ------------------------------------------------------------
//  Length to weight
//
//  The length field is metres as decimal digits. These are the values
//  Creality's own spools and the K2-RFID writers use. FilaStation (waage.py up
//  to v3.6) wrote three of them as hex grams instead, which the CFS reads as
//  nonsense lengths; they are recognised here so such tags still show the
//  weight they were meant to say.
// ------------------------------------------------------------
static uint16_t weightFromLength(const char len4[4], uint16_t* metres_out) {
  struct { const char* code; uint16_t g; } known[] = {
    {"0330", 1000}, {"0247", 750}, {"0198", 600}, {"0165", 500}, {"0082", 250},
    {"02EE", 750},  {"01C2", 600}, {"00FA", 250},   // FilaStation's hex grams
  };
  *metres_out = 0;
  for (auto& k : known) {
    if (strncasecmp(len4, k.code, 4) == 0) {
      char buf[5]; memcpy(buf, len4, 4); buf[4] = '\0';
      bool dec = isdigit((unsigned char)buf[0]) && isdigit((unsigned char)buf[1]) &&
                 isdigit((unsigned char)buf[2]) && isdigit((unsigned char)buf[3]);
      if (dec) *metres_out = (uint16_t)atoi(buf);
      return k.g;
    }
  }
  for (int i = 0; i < 4; i++) {
    if (!isdigit((unsigned char)len4[i])) return 0;
  }
  char buf[5]; memcpy(buf, len4, 4); buf[4] = '\0';
  int m = atoi(buf);
  *metres_out = (uint16_t)m;
  if (m <= 0) return 0;
  // 330 m of 1.75 mm PLA is a kilogram. Other materials differ by their
  // density, which only the spool record in Spoolman knows.
  return (uint16_t)((m * 1000 + 165) / 330);
}

static bool isHexStr(const char* s, int n) {
  for (int i = 0; i < n; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

static uint8_t hexByte(const char* s) {
  char b[3] = { s[0], s[1], '\0' };
  return (uint8_t)strtoul(b, nullptr, 16);
}

bool crealityParseRecord(const char* rec, CrealityTag* out) {
  memset(out, 0, sizeof(*out));
  out->brand = out->name = out->material = "";

  // Every field is hex digits, except the filament id: Creality's database
  // has ids like E1001 (eSUN) and P1001 (Polymaker). A wrong key, or a tag of
  // some other format that happens to open with it, decrypts to noise and
  // fails right here.
  if (!isHexStr(rec, 11) || !isHexStr(rec + 17, 23)) return false;
  for (int i = 11; i < 17; i++) {
    if (!isalnum((unsigned char)rec[i])) return false;
  }

  memcpy(out->date,        rec + 0,  5); out->date[5] = '\0';
  memcpy(out->vendor_id,   rec + 5,  4); out->vendor_id[4] = '\0';
  memcpy(out->batch,       rec + 9,  2); out->batch[2] = '\0';
  memcpy(out->filament_id, rec + 11, 6); out->filament_id[6] = '\0';
  // rec + 17: "0" then RRGGBB
  out->r = hexByte(rec + 18);
  out->g = hexByte(rec + 20);
  out->b = hexByte(rec + 22);
  out->has_color = true;
  out->weight_g = weightFromLength(rec + 24, &out->length_m);
  memcpy(out->serial,      rec + 28, 6); out->serial[6] = '\0';

  const CrealityMaterial* m = findMaterial(out->filament_id + 1);
  if (m) {
    out->brand    = m->brand;
    out->name     = m->name;
    out->material = m->material;
    out->temp_min = m->temp_min;
    out->temp_max = m->temp_max;
  } else if (strcmp(out->vendor_id, "0276") == 0) {
    out->brand = "Creality";
  }
  return true;
}

bool crealityDecode(const uint8_t sector1[3][16], CrealityTag* out) {
  uint8_t enc[48], plain[48];
  memcpy(enc, sector1, 48);
  if (!crealityDecrypt48(enc, plain)) return false;
  char rec[41];
  memcpy(rec, plain, 40);
  rec[40] = '\0';
  return crealityParseRecord(rec, out);
}

// ------------------------------------------------------------
//  Writing
// ------------------------------------------------------------

bool crealityEncrypt48(const uint8_t in[48], uint8_t out[48]) {
  return aesEcb(DATA_KEY, MBEDTLS_AES_ENCRYPT, in, out, 48);
}

bool crealityEncryptRecord(const char rec40[40], uint8_t out[48]) {
  uint8_t plain[48];
  memset(plain, ' ', sizeof(plain));
  memcpy(plain, rec40, 40);
  return crealityEncrypt48(plain, out);
}

// Upper case letters, digits and '+', nothing else: "Hyper PLA-CF" -> "HYPERPLACF".
static void normName(const char* in, char* out, size_t out_len) {
  size_t o = 0;
  for (const char* p = in; p && *p && o + 1 < out_len; p++) {
    const unsigned char c = (unsigned char)*p;
    if (isalnum(c) || c == '+') out[o++] = (char)toupper(c);
  }
  out[o] = '\0';
}

struct ProductId { const char* key; const char* id; };
static const ProductId CREALITY_PRODUCTS[] = {
  {"HYPERPLA","01001"}, {"HYPERLWPLA","01002"}, {"HYPERSTARDUST","01004"},
  {"SOLEYINULTRAPLA","01601"}, {"HYPERPLACF","02001"}, {"HYPERABS","03001"},
  {"CRPLA","04001"}, {"CRSILK","05001"}, {"CRPETG","06001"},
  {"HYPERPETG","06002"}, {"HYPERPETGCF","06003"}, {"CRABS","07001"},
  {"HYPERPC","07002"}, {"ENDERPLA","08001"}, {"ENPLA+","09001"},
  {"ENPLAPLUS","09001"}, {"ENDERFASTPLA","09002"}, {"HPTPU","10001"},
  {"CRNYLON","11001"}, {"HYPERPPACF","12002"}, {"HYPERPAHTCF","12003"},
  {"HYPERPA612CF","12004"}, {"HYPERPA6CF","12005"}, {"CRPLACARBON","13001"},
  {"CRPLAMATTE","14001"}, {"CRPLAFLUO","15001"}, {"CRTPU","16001"},
  {"CRWOOD","17001"}, {"HPULTRAPLA","18001"}, {"HPASA","19001"},
  {"HYPERASA","19001"}, {"HYPERMARBLE","29001"}, {nullptr, nullptr} };
static const ProductId ESUN_PRODUCTS[] = {
  {"PLA+","E1001"}, {"PLAPLUS","E1001"}, {"PLALW","00035"}, {nullptr, nullptr} };
static const ProductId POLYMAKER_PRODUCTS[] = {
  {"PANCHROMAPLASATIN","P1001"}, {"POLYSONICPLAPRO","P1002"},
  {"PANCHROMAPLAMATTE","P1003"}, {nullptr, nullptr} };
struct Brand { const char* key; const ProductId* table; };
static const Brand BRANDS[] = {
  {"CREALITY", CREALITY_PRODUCTS}, {"ESUN", ESUN_PRODUCTS},
  {"POLYMAKER", POLYMAKER_PRODUCTS}, {nullptr, nullptr} };

// Longest key contained in the normalised text.
static const char* findProduct(const ProductId* table, const char* text) {
  char n[96]; normName(text, n, sizeof(n));
  const char* best = nullptr; size_t best_len = 0;
  for (const ProductId* p = table; p->key; p++) {
    const size_t l = strlen(p->key);
    if (l > best_len && strstr(n, p->key)) { best = p->id; best_len = l; }
  }
  return best;
}

static const ProductId GENERIC_IDS[] = {
  {"PLA","00001"}, {"PLA_SILK","00002"}, {"PLA_MATTE","00001"},
  {"PETG","00003"}, {"ABS","00004"}, {"TPU","00005"}, {"PLA_CF","00006"},
  {"ASA","00007"}, {"PA","00008"}, {"NYLON","00008"}, {"PA_CF","00009"},
  {"BVOH","00010"}, {"PVA","00011"}, {"HIPS","00012"}, {"PET_CF","00013"},
  {"PETG_CF","00014"}, {"PA6_CF","00015"}, {"PAHT_CF","00016"}, {"PPS","00017"},
  {"PPS_CF","00018"}, {"PP","00019"}, {"PET","00020"}, {"PC","00021"},
  {"PA612_CF","00022"}, {"PA12_CF","00025"}, {"PETG_GF","00027"},
  {"PP_CF","00031"}, {"PCTG","00032"}, {"ASA_CF","00033"}, {"PA_GF","00034"},
  {"PA6_GF","00034"}, {"SILK_PLA","00002"}, {"MATTE_PLA","00001"}, {nullptr, nullptr} };

// The material type as a whole word, longest first: "Overture Matte PLA" ->
// PLA, "xyz PETG-CF" -> PETG-CF, "Geeetech HS-PLA" -> PLA.
static const char* findGeneric(const char* text) {
  if (!text || !*text) return nullptr;
  char w[100]; size_t o = 0; bool sep = true;
  w[o++] = '_';
  for (const char* p = text; *p && o + 2 < sizeof(w); p++) {
    const unsigned char c = (unsigned char)*p;
    if (isalnum(c)) { w[o++] = (char)toupper(c); sep = false; }
    else if (!sep)  { w[o++] = '_'; sep = true; }
  }
  if (!sep) w[o++] = '_';
  w[o] = '\0';
  const char* best = nullptr; size_t best_len = 0;
  for (const ProductId* p = GENERIC_IDS; p->key; p++) {
    char k[24]; snprintf(k, sizeof(k), "_%s_", p->key);
    const size_t l = strlen(p->key);
    if (l > best_len && strstr(w, k)) { best = p->id; best_len = l; }
  }
  return best;
}

void crealityFilamentIdFor(const char* vendor, const char* name, const char* material,
                           char out[7]) {
  char v[48]; normName(vendor ? vendor : "", v, sizeof(v));
  const char* id = nullptr;
  for (const Brand* b = BRANDS; b->key && !id; b++) {
    if (v[0] && strstr(v, b->key)) {
      id = findProduct(b->table, name ? name : "");
      // A name that leaves the material out or puts the colour first -
      // "Gold Hyper" with material PLA, 14.10.2026 - still names the
      // product once the material is behind it: "Gold Hyper PLA".
      if (!id && name && *name && material && *material) {
        char both[96];
        snprintf(both, sizeof(both), "%s %s", name, material);
        id = findProduct(b->table, both);
      }
      if (!id) id = findProduct(b->table, material ? material : "");
      break;
    }
  }
  if (!id) id = findProduct(CREALITY_PRODUCTS, material ? material : "");
  if (!id) id = findGeneric(material);
  if (!id) id = findGeneric(name);
  if (!id) id = "00001";
  snprintf(out, 7, "1%s", id);
}

void crealityLengthCodeFor(float net_g, char out[5]) {
  struct B { int g; const char* code; };
  static const B buckets[] = { {250,"0082"}, {500,"0165"}, {600,"0198"},
                               {750,"0247"}, {1000,"0330"} };
  if (net_g <= 0) net_g = 1000;
  const char* best = "0330"; float best_d = 1e9f;
  for (const B& b : buckets) {
    const float d = fabsf(net_g - (float)b.g);
    if (d < best_d) { best_d = d; best = b.code; }
  }
  snprintf(out, 5, "%s", best);
}

bool crealityBuildRecord(const CrealityRecordIn& in, char out[41]) {
  char date[6];
  if (in.month >= 1 && in.month <= 12 && in.day >= 1 && in.day <= 31) {
    // Month as one hex digit, day as BCD, year as two hex digits - the way
    // FilaStation writes it.
    snprintf(date, sizeof(date), "%1X%02X%02X", in.month,
             ((in.day / 10) << 4) | (in.day % 10), (unsigned)(in.year % 100));
  } else {
    snprintf(date, sizeof(date), "AB124");
  }
  char fid[7]; crealityFilamentIdFor(in.vendor, in.name, in.material, fid);
  char color[7] = "808080";
  const char* c = in.color_hex ? in.color_hex : "";
  if (*c == '#') c++;
  if (strlen(c) >= 6) {
    bool hex = true;
    for (int i = 0; i < 6; i++) if (!isxdigit((unsigned char)c[i])) hex = false;
    if (hex) for (int i = 0; i < 6; i++) color[i] = (char)toupper((unsigned char)c[i]);
  }
  char len[5]; crealityLengthCodeFor(in.net_g, len);
  const int serial = in.spool_id > 0 ? in.spool_id % 1000000 : 1;
  const int n = snprintf(out, 41, "%s0276A2%s0%s%s%06d000000", date, fid, color, len, serial);
  return n == 40;
}
