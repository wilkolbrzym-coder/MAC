// ===========================================================================
//  meta-auth-core -- version declaration
//
//  This header is the authoritative version of the project. The build system
//  reads it back and refuses to configure when `project(VERSION ...)` in
//  CMakeLists.txt disagrees (see cmake/MetaAuthVersion.cmake), which keeps a
//  vendored copy of `include/` honest without giving the build system the
//  power to change what the headers claim.
// ===========================================================================
#ifndef META_AUTH_VERSION_HPP
#define META_AUTH_VERSION_HPP

#include <cstdint>
#include <string_view>

// Numeric components. Parsed by cmake/MetaAuthVersion.cmake: keep the spelling
// of these three definitions exactly as it is.
inline constexpr std::uint32_t META_AUTH_VERSION_MAJOR = 0;
inline constexpr std::uint32_t META_AUTH_VERSION_MINOR = 1;
inline constexpr std::uint32_t META_AUTH_VERSION_PATCH = 0;

// Semantic version literal. Parsed by cmake/MetaAuthVersion.cmake as well.
inline constexpr std::string_view META_AUTH_VERSION_STRING = "0.1.0";

namespace meta_auth {

/// Numeric version, packed as 0xMMmmpp for cheap comparisons.
[[nodiscard]] constexpr auto version_packed() noexcept -> std::uint32_t {
    return (META_AUTH_VERSION_MAJOR << 16U) | (META_AUTH_VERSION_MINOR << 8U)
           | META_AUTH_VERSION_PATCH;
}

/// Project name as it appears in packages and diagnostics.
inline constexpr std::string_view project_name = "meta-auth-core";

/// Semantic version of the headers currently being compiled.
inline constexpr std::string_view version = META_AUTH_VERSION_STRING;

/// One-line description shared by the package metadata and the CLI banner.
inline constexpr std::string_view project_description =
    "Compile-time user/device authentication and object-capability sandbox";

/// SPDX identifier of the license this project is distributed under.
inline constexpr std::string_view license_identifier = "Apache-2.0";

} // namespace meta_auth

#endif // META_AUTH_VERSION_HPP
