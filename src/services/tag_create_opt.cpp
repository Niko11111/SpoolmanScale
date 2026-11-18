#include "tag_create_opt.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "../app/app_state.h"
#include "../openprinttag/opt_scan.h"

bool tagCreateInputFromOpenPrintTag(TagCreateInput* in) {
  if (!optTagOnReader()) return false;
  const OptTag& t = optLastTag();
  if (!t.brand[0] || t.color_count == 0) return false;

  snprintf(in->vendor, sizeof(in->vendor), "%s", t.brand);
  snprintf(in->material, sizeof(in->material), "%s", g_tag.material);
  // No product line: the material name is the material and the colour
  // ("PLA Galaxy Black"), so the filament is named by its colour, as
  // SpoolmanDB names Prusament.
  snprintf(in->product, sizeof(in->product), "%s", g_tag.material);
  optColorName(t, in->color_name, sizeof(in->color_name));
  snprintf(in->color_name_en, sizeof(in->color_name_en), "%s", in->color_name);
  // Found again by its UID, E0:04:... as the scan path prints it.
  snprintf(in->link_id, sizeof(in->link_id), "%s", g_tag.uid_str);
  tagCreateColorsFromTag(in);
  // The filament as sold (nominal), else what was weighed in (actual).
  const float net = t.nominal_weight_g > 0 ? t.nominal_weight_g : t.actual_weight_g;
  in->net_weight_g = net > 0 ? (int)lroundf(net) : 0;
  // The maker's own figure for this spool, not a default.
  in->spool_weight_g = t.container_weight_g > 0 ? (int)lroundf(t.container_weight_g) : 0;
  in->spool_weight_default = false;
  in->diameter_mm = t.diameter_mm > 0.0f ? t.diameter_mm : TAG_CREATE_DIAMETER_MM;
  in->temp_min = t.print_min_c;
  in->temp_max = t.print_max_c;
  in->dry_temp_c = t.dry_c;
  in->dry_hours = g_tag.dry_hours;
  in->names_known = true;
  // The tag's density, used where no database has one (densityOrAsk()).
  if (t.density > 0.0f) in->user_density = t.density;
  return true;
}
