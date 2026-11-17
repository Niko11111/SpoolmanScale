# Keeps the NXP-licensed files of the PN7160 library out of the build.
#
# The Elechouse library (platformio.ini, pinned by commit) is MIT, except for
# the NDEF, P2P and card emulation sources it carries over from NXP, whose
# header says "Reproduction in whole or in part is prohibited". This firmware
# is GPL and never uses them: hardware/nfc_pn7160.cpp speaks NCI through the
# library's transport and init only. A file that is not compiled cannot end up
# in the binary; the linker drops the library functions that would call into
# them, because nothing here calls those either.
Import("env")

NXP_LICENSED = [
    "*ELECHOUSE*/src/RW_NDEF*.cpp",
    "*ELECHOUSE*/src/P2P_NDEF.cpp",
    "*ELECHOUSE*/src/T4T_NDEF_emu.cpp",
    "*ELECHOUSE*/src/tool.cpp",
    "*ELECHOUSE*/src/ndef_helper.cpp",
]

def skip(env, node):
    return None

for pattern in NXP_LICENSED:
    env.AddBuildMiddleware(skip, pattern)
