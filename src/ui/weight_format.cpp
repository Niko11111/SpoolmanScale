#include "weight_format.h"

#include <stdio.h>

#include "services/user_options.h"

void fmtG(char* buf, size_t len, float val) {
  if (val > -0.5f && val < 0.5f) val = 0.0f;
  if (g_whole_gram) snprintf(buf, len, "%.0f g", val);
  else              snprintf(buf, len, "%.1f g", val);
}
