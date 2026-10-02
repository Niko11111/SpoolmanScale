# Builds LVGL for speed (-O2) instead of size (-Os), which the framework sets
# for everything. Rendering is most of what a frame costs. Measured with the
# render bench (02.10.2026): a scrolled list frame 40.6 -> 34.6 ms, for about
# 36 kB more firmware.
Import("env")

def lvgl_o2(env, node):
    return env.Object(node, CCFLAGS=env["CCFLAGS"] + ["-O2"])

env.AddBuildMiddleware(lvgl_o2, "*lvgl/src/*")
