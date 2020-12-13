#if !defined(__SSR_EXTERN_DEF_H__)
#define __SSR_EXTERN_DEF_H__

#if defined(BUILDING_SSR_NATIVE_SHARED) && defined(USING_SSR_NATIVE_SHARED)
#error "Define either BUILDING_SSR_NATIVE_SHARED or USING_SSR_NATIVE_SHARED, not both."
#endif

#ifdef _WIN32
/* Windows - set up dll import/export decorators. */
# if defined(BUILDING_SSR_NATIVE_SHARED)
/* Building shared library. */
#   define SSR_EXTERN __declspec(dllexport)
# elif defined(USING_SSR_NATIVE_SHARED)
/* Using shared library. */
#   define SSR_EXTERN __declspec(dllimport)
# else
/* Building static library. */
#   define SSR_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define SSR_EXTERN __attribute__((visibility("default")))
#else
# define SSR_EXTERN /* nothing */
#endif

#endif // __SSR_EXTERN_DEF_H__
