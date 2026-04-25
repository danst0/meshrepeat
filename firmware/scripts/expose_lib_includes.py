# Pre-build hook: expose every installed lib_deps' src/ directory on the
# global CPPPATH so that source files included via build_src_filter
# (out-of-src tree, e.g. lib/meshcore/src/*.cpp) can resolve transitive
# headers like <ed_25519.h> from rweather/Crypto.
#
# Background: PlatformIO normally adds a library's src/ to CPPPATH only
# for the LDF-discovered consumers of that library. When MeshCore is
# excluded via lib_ignore and pulled in via build_src_filter instead,
# its compilations are attached to the project, but the project doesn't
# auto-inherit each library's src/ — only direct includes in src/ would
# trigger LDF resolution.

import glob
import os

Import("env")  # noqa: F821  - provided by PlatformIO

libdeps = env.subst("$PROJECT_LIBDEPS_DIR")  # noqa: F821
env_name = env.subst("$PIOENV")              # noqa: F821

candidates = [
    os.path.join(libdeps, env_name, "*"),
    os.path.join(libdeps, env_name, "*", "src"),
]
added = []
for pattern in candidates:
    for path in sorted(glob.glob(pattern)):
        if not os.path.isdir(path):
            continue
        # Skip top-level lib dirs without an src/; we already get those
        # via the second candidate pattern.
        if pattern.endswith("*") and os.path.isdir(os.path.join(path, "src")):
            continue
        env.Append(CPPPATH=[path])  # noqa: F821
        added.append(path)

# Plus MeshCore's own src — needed because lib_ignore=MeshCore drops PIO's
# automatic include.
project_dir = env.subst("$PROJECT_DIR")  # noqa: F821
mc_paths = [
    os.path.join(project_dir, "lib", "meshcore", "src"),
    os.path.join(project_dir, "lib", "meshcore", "variants", "lilygo_tbeam_SX1276"),
]
for p in mc_paths:
    if os.path.isdir(p):
        env.Append(CPPPATH=[p])  # noqa: F821
        added.append(p)

print(f"[expose_lib_includes] added {len(added)} include paths")
for p in added:
    print(f"  + {p}")
