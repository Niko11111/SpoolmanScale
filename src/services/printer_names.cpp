#include "services/printer_names.h"

#include <string.h>

static const size_t SEPARATOR_LEN = sizeof(PRINTER_NAME_SEPARATOR) - 1;

// True when the list holds this model as a whole entry, so "D110" does not
// match inside "D110 M".
static bool listed(const char* list, const char* model, size_t len) {
  if (!list) return false;
  for (const char* at = list; *at;) {
    const char* end = strstr(at, PRINTER_NAME_SEPARATOR);
    const size_t n = end ? (size_t)(end - at) : strlen(at);
    if (n == len && strncmp(at, model, len) == 0) return true;
    if (!end) break;
    at = end + SEPARATOR_LEN;
  }
  return false;
}

void printerNameEach(const char* names, const char* untried, PrinterNameFn fn, void* ctx) {
  if (!names || !fn) return;
  for (const char* at = names; *at;) {
    const char* end = strstr(at, PRINTER_NAME_SEPARATOR);
    const size_t n = end ? (size_t)(end - at) : strlen(at);
    fn(at, n, listed(untried, at, n), ctx);
    if (!end) break;
    at = end + SEPARATOR_LEN;
  }
}

// Where a brand first shows up in the list: its place among the brands.
static int brandRank(const char* const* brands, int n, int i) {
  for (int j = 0; j < n; j++)
    if (strcmp(brands[j], brands[i]) == 0) return j;
  return i;
}

static bool before(const char* const* brands, const char* const* names, int n, int a, int b) {
  const int ra = brandRank(brands, n, a), rb = brandRank(brands, n, b);
  if (ra != rb) return ra < rb;
  return strcmp(names[a], names[b]) < 0;
}

// Insertion sort: a dozen models, and it keeps equal entries in place.
void printerSortByBrand(const char* const* brands, const char* const* names, int* order, int n) {
  for (int i = 0; i < n; i++) order[i] = i;
  for (int i = 1; i < n; i++) {
    const int v = order[i];
    int j = i - 1;
    while (j >= 0 && before(brands, names, n, v, order[j])) {
      order[j + 1] = order[j];
      j--;
    }
    order[j + 1] = v;
  }
}
