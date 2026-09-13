#include "loop_task.h"

#include <Arduino.h>

static TaskHandle_t s_loop = nullptr;

void loopTaskRemember() { s_loop = xTaskGetCurrentTaskHandle(); }

bool onLoopTask() {
  return !s_loop || xTaskGetCurrentTaskHandle() == s_loop;
}
