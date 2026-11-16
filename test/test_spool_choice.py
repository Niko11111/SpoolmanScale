"""Compile the production empty spool rules and read the decisions back: the
built-in catalog, the last choices, their NVS line, and which tare a card
weighs against (services/spool_choice.h)."""
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).parents[1]
source = r"""
#include "services/spool_choice.h"
#include "services/tare_chain.h"
#include <cassert>
#include <cstring>
#include <strings.h>

static SpoolChoice typed(int grams) {
  SpoolChoice c;
  spoolChoiceClear(&c);
  c.weight_g = (uint16_t)grams;
  c.source = SCS_TYPED;
  return c;
}

int main() {
  // The catalog: makers by name, each one's most common spool first.
  const int sunlu = spoolCatalogFindMaker("SUNLU");
  assert(sunlu >= 0 && strcmp(spoolCatalogMakerName(sunlu), "Sunlu") == 0);
  assert(spoolCatalogSpoolCount(sunlu) == 2);
  SpoolChoice c;
  assert(spoolCatalogChoice(sunlu, 0, &c));
  assert(c.weight_g == 189 && c.net_g == 1000 && c.kind == SPOOL_KIND_PLASTIC);
  assert(c.source == SCS_CATALOG && strcmp(c.name, "Sunlu") == 0);
  assert(!spoolCatalogChoice(sunlu, 2, &c) && !spoolCatalogChoice(-1, 0, &c));
  // A name is found by its letters and digits, whatever the spelling.
  assert(spoolCatalogFindMaker("bambu-lab") == spoolCatalogFindMaker("Bambu Lab"));
  assert(spoolCatalogFindMaker("Bambu Lab") >= 0);
  assert(spoolCatalogFindMaker("") == -1 && spoolCatalogFindMaker("No Such Maker") == -1);
  assert(spoolCatalogMakerName(spoolCatalogMakerCount())[0] == '\0');
  for (int m = 1; m < spoolCatalogMakerCount(); m++)
    assert(strcasecmp(spoolCatalogMakerName(m - 1), spoolCatalogMakerName(m)) < 0);

  // The tare: a choice wins over the chain and counts as stored on the spool...
  uint8_t from = TARE_VENDOR;
  TareQuality q = TARE_Q_DEFAULT;
  SpoolChoice none;
  spoolChoiceClear(&none);
  assert(spoolChoiceTare(none, 250, &from, &q) == 250 && from == TARE_VENDOR && q == TARE_Q_DEFAULT);
  assert(spoolChoiceTare(typed(189), 250, &from, &q) == 189 && from == TARE_SPOOL && q == TARE_Q_KNOWN);
  // ...and the 1000 g Bambu refill on a 189 g Sunlu spool reads full.
  assert(1189 - spoolChoiceTare(typed(189), 250, nullptr, nullptr) == 1000);

  // The last choices: newest first, no spool twice, two at most.
  SpoolChoice recent[SPOOL_RECENT_MAX];
  for (auto& r : recent) spoolChoiceClear(&r);
  spoolRecentPush(recent, typed(162));
  spoolRecentPush(recent, c);                 // Sunlu 189
  assert(recent[0].weight_g == 189 && recent[1].weight_g == 162);
  spoolRecentPush(recent, typed(162));
  assert(recent[0].weight_g == 162 && recent[1].weight_g == 189);
  spoolRecentPush(recent, typed(98));
  assert(recent[0].weight_g == 98 && recent[1].weight_g == 162);
  spoolRecentPush(recent, none);              // nothing chosen changes nothing
  assert(recent[0].weight_g == 98);

  // The NVS line holds every field and refuses what it cannot read.
  char line[SPOOL_CHOICE_TEXT_MAX];
  c.catalog_id = 7;
  assert(spoolChoiceEncode(c, line, sizeof(line)) && strcmp(line, "189|1|1|1000|7|Sunlu") == 0);
  SpoolChoice back;
  assert(spoolChoiceDecode(line, &back) && spoolChoiceSame(back, c));
  assert(back.net_g == 1000 && back.kind == SPOOL_KIND_PLASTIC && back.catalog_id == 7);
  assert(spoolChoiceDecode("98|2|0|0|0|", &back) && back.weight_g == 98 && back.name[0] == '\0');
  assert(!spoolChoiceDecode("", &back) && !spoolChoiceDecode("0|2|0|0|0|", &back));
  assert(!spoolChoiceDecode("189|1|1|1000", &back) && !spoolChoiceDecode("abc|1|1|0|0|x", &back));
  assert(!spoolChoiceDecode("189|9|1|0|0|x", &back) && !spoolChoiceDecode("70000|1|1|0|0|x", &back));
  // The user's own: a name and a weight the web page accepts, kept as lines.
  SpoolChoice mine[SPOOL_MINE_MAX];
  assert(spoolMineMake("Sunlu Karton", 152, &mine[0]) && mine[0].source == SCS_MINE);
  assert(spoolMineMake("Gedruckt PETG", 98, &mine[1]));
  assert(!spoolMineValid("", 100) && !spoolMineValid("a|b", 100) && !spoolMineValid("a\nb", 100));
  assert(!spoolMineValid("x", SPOOL_MINE_MIN_G - 1) && !spoolMineValid("x", SPOOL_MINE_MAX_G + 1));
  assert(!spoolMineValid("0123456789012345678901234567890123", 100));
  char all[SPOOL_MINE_TEXT_MAX];
  assert(spoolMineEncode(mine, 2, all, sizeof(all)));
  assert(strcmp(all, "152|3|0|0|0|Sunlu Karton\n98|3|0|0|0|Gedruckt PETG") == 0);
  SpoolChoice read[SPOOL_MINE_MAX];
  assert(spoolMineDecode(all, read) == 2 && spoolChoiceSame(read[1], mine[1]));
  // A broken line, or one that is not the user's own, is skipped.
  assert(spoolMineDecode("152|3|0|0|0|A\nbroken\n189|1|1|1000|0|Sunlu\n98|3|0|0|0|B", read) == 2);
  assert(strcmp(read[1].name, "B") == 0);
  assert(spoolMineDecode("", read) == 0 && spoolMineDecode(nullptr, read) == 0);
  for (auto& m : mine) assert(spoolMineMake("Twelve", 100, &m));
  assert(spoolMineEncode(mine, SPOOL_MINE_MAX, all, sizeof(all)));
  assert(spoolMineDecode(all, read) == SPOOL_MINE_MAX);

  // The backend's: the card's maker first, each spool once, at most max.
  SpoolChoice srv[5], pick[SPOOL_SERVER_MAX];
  assert(spoolMineMake("eSun", 240, &srv[0]) && spoolMineMake("Sunlu 250g - Plastic", 250, &srv[1]));
  assert(spoolMineMake("Polymaker", 140, &srv[2]) && spoolMineMake("SUNLU", 189, &srv[3]));
  srv[4] = srv[0];
  for (auto& x : srv) x.source = SCS_SERVER;
  assert(spoolServerPick(srv, 5, "Sunlu", pick, SPOOL_SERVER_MAX) == 4);
  assert(pick[0].weight_g == 250 && pick[1].weight_g == 189 && pick[2].weight_g == 240 && pick[3].weight_g == 140);
  assert(spoolServerPick(srv, 5, "", pick, 2) == 2 && pick[0].weight_g == 240);
  assert(spoolServerPick(nullptr, 0, "x", pick, 2) == 0);

  SpoolChoice piped = typed(100);
  strcpy(piped.name, "a|b");
  assert(!spoolChoiceEncode(piped, line, sizeof(line)));
  return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    cpp = Path(tmp) / "test.cpp"
    binary = Path(tmp) / "test"
    cpp.write_text(source, encoding="utf-8")
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(root / "src"),
                    str(cpp), str(root / "src/services/spool_choice.cpp"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("empty spool choice rules ok")
