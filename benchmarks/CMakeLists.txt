# ---------------------------------------------------------------------------
# Micro-benchmarks.
#
# Built in the `bench` preset, which disables hardening: the question here is
# what the library costs, not what a hardened build costs.
#
# `meta_auth_bench --check` is not a separate mode: the constant-time section
# always gates on its own measured spread, so a regression fails the run rather
# than being reported and ignored. CI runs this benchmark for that reason.
# ---------------------------------------------------------------------------
add_executable(meta_auth_bench meta_auth_bench.cpp)
target_link_libraries(meta_auth_bench PRIVATE meta_auth::meta_auth)
set_target_properties(meta_auth_bench PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
