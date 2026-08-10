#pragma once

#include <stddef.h>

bool extractBambuSubtype(const char* material, char* out_kw, size_t out_size);
bool isSupportMaterial(const char* material_filter);
bool isSupportSpoolmanMat(const char* mat);
bool containsIgnoreCase(const char* haystack, const char* needle);
int colorDistance(const char* hex_a, const char* hex_b);
