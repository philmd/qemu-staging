/* Define target_phys_addr_t if it exists.  */

#ifndef TARGPHYS_H
#define TARGPHYS_H

#ifdef TARGET_PHYS_ADDR_BITS
/* target_phys_addr_t is the type of a physical address (its size can
   be different from 'target_ulong').  */

#if TARGET_PHYS_ADDR_BITS == 32
typedef uint32_t target_phys_addr_t;
#define TARGET_PHYS_ADDR_MAX UINT32_MAX
#define TARGET_FMT_plx "%08x"
/* Format strings for printing target_phys_addr_t types.
 * These are recommended over the less flexible TARGET_FMT_plx,
 * which is retained for the benefit of existing code.
 */
#define PRIdPLX PRId32
#define PRIiPLX PRIi32
#define PRIoPLX PRIo32
#define PRIuPLX PRIu32
#define PRIxPLX PRIx32
#define PRIXPLX PRIX32
#elif TARGET_PHYS_ADDR_BITS == 64
typedef uint64_t target_phys_addr_t;
#define TARGET_PHYS_ADDR_MAX UINT64_MAX
#define TARGET_FMT_plx "%016" PRIx64
#define PRIdPLX PRId64
#define PRIiPLX PRIi64
#define PRIoPLX PRIo64
#define PRIuPLX PRIu64
#define PRIxPLX PRIx64
#define PRIXPLX PRIX64
#endif
#endif

#endif
