#pragma once

// A render benchmark that needs no hand on the panel: it builds a spool list
// like the link flow's own, scrolls it in fixed steps and redraws after every
// step, and writes what a frame cost into the log. Two hand-scrolled runs
// never draw the same frames; this does, so two firmware builds can be
// compared by one number each. It measures speed only - how a frame looks
// while it is being written still needs eyes on the panel.

// From the web route: parks the run for the loop. Nothing is drawn here.
void renderBenchRequest();

// From appLoop(), outside every LVGL callback. Runs a parked request: about
// two seconds in which the panel shows the test list and nothing else moves.
void renderBenchTick();
