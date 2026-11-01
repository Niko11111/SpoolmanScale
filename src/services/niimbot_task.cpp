#include "services/niimbot_task.h"

// The first status version of each protocol (niimbluelib's
// parsePrinterStatusDataResponse).
#define NB_STATUS_V3_FROM  204
#define NB_STATUS_V4_FROM  300
#define NB_STATUS_V5_FROM  302
#define NB_PROTO_V4          4

uint8_t niimbotProtocolFromStatus(unsigned version) {
  if (version >= NB_STATUS_V5_FROM) return 5;
  if (version >= NB_STATUS_V4_FROM) return 4;
  if (version >= NB_STATUS_V3_FROM) return 3;
  return 0;
}

NiimbotTask niimbotTaskFor(uint16_t model_id, NiimbotTask table_task, uint8_t proto) {
  if (model_id == NB_ID_D110_M && proto == NB_PROTO_V4) return NB_TASK_V4;
  return table_task;
}

bool niimbotIsD110(uint16_t model_id) {
  return model_id == NB_ID_D110_A || model_id == NB_ID_D110_B || model_id == NB_ID_D110_M;
}
