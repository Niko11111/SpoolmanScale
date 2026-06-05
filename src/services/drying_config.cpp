#include "drying_config.h"

uint8_t g_dry_mode = 0;
int g_dry_man_yellow = 30;
int g_dry_man_red = 90;

const char* DRY_MAT_NAMES[] = { "PLA", "PETG", "ABS", "ASA", "TPU", "PA", "PC" };
const int DRY_MAT_DEF_YELLOW[] = { 180, 90, 90, 90, 30, 7, 30 };
const int DRY_MAT_DEF_RED[] = { 365, 180, 180, 180, 90, 30, 90 };
const int DRY_MAT_COUNT = 7;

int g_dry_mat_yellow[7];
int g_dry_mat_red[7];
bool g_dry_mat_sealed[7];
float g_dry_mult_sealed = 2.0f;
