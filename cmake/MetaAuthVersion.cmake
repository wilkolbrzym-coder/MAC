# ---------------------------------------------------------------------------
# MetaAuthVersion -- keep `include/meta_auth/version.hpp` and `project(...)`
# in agreement.
#
# The headers are the single source of truth for the version because the
# library is header-only and must remain usable when it is vendored into a
# build that knows nothing about this CMake project. That makes the build
# system a *validator* of the version, not the author of it: a mismatch is a
# release-engineering defect and is reported as a hard configuration error
# instead of producing artifacts that lie about what they are.
# ---------------------------------------------------------------------------
set(_meta_auth_version_header "${CMAKE_CURRENT_SOURCE_DIR}/include/meta_auth/version.hpp")

if(NOT EXISTS "${_meta_auth_version_header}")
    message(FATAL_ERROR
        "include/meta_auth/version.hpp is missing. It is the authoritative "
        "declaration of the project version and must exist for the build to "
        "be able to validate it.")
endif()

file(READ "${_meta_auth_version_header}" _meta_auth_version_contents)

foreach(_component MAJOR MINOR PATCH)
    string(TOLOWER "${_component}" _component_lower)
    if(NOT _meta_auth_version_contents MATCHES
            "META_AUTH_VERSION_${_component} = ([0-9]+)")
        message(FATAL_ERROR
            "include/meta_auth/version.hpp does not define "
            "META_AUTH_VERSION_${_component}; expected a line of the form "
            "'inline constexpr std::uint32_t META_AUTH_VERSION_${_component} = <n>;'.")
    endif()
    set(_meta_auth_header_${_component_lower} "${CMAKE_MATCH_1}")
endforeach()

if(NOT _meta_auth_version_contents MATCHES
        "META_AUTH_VERSION_STRING = \"([0-9]+\\.[0-9]+\\.[0-9]+)\"")
    message(FATAL_ERROR
        "include/meta_auth/version.hpp does not define META_AUTH_VERSION_STRING "
        "with a semantic version literal.")
endif()
set(_meta_auth_header_string "${CMAKE_MATCH_1}")

set(_meta_auth_header_version
    "${_meta_auth_header_major}.${_meta_auth_header_minor}.${_meta_auth_header_patch}")

if(NOT _meta_auth_header_version STREQUAL PROJECT_VERSION)
    message(FATAL_ERROR
        "Version mismatch between the build description and the headers.\n"
        "  CMakeLists.txt project(VERSION ...) : ${PROJECT_VERSION}\n"
        "  include/meta_auth/version.hpp       : ${_meta_auth_header_version}\n"
        "Update both together: the header is what installed consumers read.")
endif()

if(NOT _meta_auth_header_string STREQUAL PROJECT_VERSION)
    message(FATAL_ERROR
        "META_AUTH_VERSION_STRING ('${_meta_auth_header_string}') does not match "
        "the numeric components ('${_meta_auth_header_version}') in "
        "include/meta_auth/version.hpp.")
endif()

unset(_meta_auth_version_contents)
unset(_component)
unset(_component_lower)
