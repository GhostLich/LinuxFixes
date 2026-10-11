#include <windows.h>
#include <stddef.h>

#define MI_HAS_TLS_SLOT
#define MI_TLS_SLOT mi_teb_slot

extern size_t mi_teb_slot;

static inline void *mi_prim_tls_slot(size_t slot)
{
	char *teb = (char *)NtCurrentTeb();
	if (slot < 64) {
		return ((void **)(teb + 0x1480))[slot];
	}
	void **expansion = *(void ***)(teb + 0x1780);
	return expansion ? expansion[slot - 64] : NULL;
}

static inline void mi_prim_tls_slot_set(size_t slot, void *value)
{
	TlsSetValue((DWORD)slot, value);
}
