#pragma once

#if defined(_WIN32)

#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <malloc.h>
#  define ECDH_ALLOCA(bytes) _malloca(bytes)

#  ifdef ECDH_P256_BUILD_SHARED
#    ifdef ECDH_P256_EXPORTS
#      define ATTR_SHARED __declspec(dllexport)
#    else
#      define ATTR_SHARED __declspec(dllimport)
#    endif
#  else
#    define ATTR_SHARED
#  endif

#elif defined(linux)

#  include <alloca.h>
#  define ECDH_ALLOCA(bytes) alloca(bytes)

#  if defined(ECDH_P256_BUILD_SHARED) && defined(ECDH_P256_EXPORTS)
#    define ATTR_SHARED __attribute__((visibility("default")))
#  else
#    define ATTR_SHARED
#  endif

#else

#  define ATTR_SHARED

#endif
