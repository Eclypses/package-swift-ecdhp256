#pragma once

#if defined(_WIN32)

#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <malloc.h>
#  define ECDH_ALLOCA(bytes) _malloca(bytes)

#elif defined(linux)
#  include <alloca.h>
#else

#endif
