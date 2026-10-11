#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include "mimalloc.h"

size_t mi_teb_slot;

static void __attribute__((constructor(101))) tebSlotInit(void)
{
	mi_teb_slot = TlsAlloc();
}

static HANDLE crtHeap;
static unsigned char *stubPage;
static size_t stubUsed;

struct patch {
	unsigned char *site;
	unsigned char saved[5];
	unsigned char *stub;
	size_t guard;
};

static struct patch patches[24];
static int patchCount;
static HANDLE threadHandles[256];
static int threadCount;

static void *hookMalloc(size_t size)
{
	if (size <= 8) {
		size = 16;
	}
	return mi_malloc(size);
}

static void *hookCalloc(size_t count, size_t size)
{
	if (size && count > SIZE_MAX / size) {
		return NULL;
	}
	if (count * size <= 8) {
		return mi_zalloc(16);
	}
	return mi_calloc(count, size);
}

static void hookFree(void *p)
{
	if (!p) {
		return;
	}
	if (mi_is_in_heap_region(p)) {
		mi_free(p);
	} else {
		HeapFree(crtHeap, 0, p);
	}
}

static size_t hookMsize(void *p)
{
	if (!p) {
		return 0;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_usable_size(p);
	}
	return HeapSize(crtHeap, 0, p);
}

static void *hookRealloc(void *p, size_t size)
{
	if (size && size <= 8) {
		size = 16;
	}
	if (!p) {
		return hookMalloc(size);
	}
	if (mi_is_in_heap_region(p)) {
		if (size == 0) {
			mi_free(p);
			return NULL;
		}
		return mi_realloc(p, size);
	}
	if (size == 0) {
		HeapFree(crtHeap, 0, p);
		return NULL;
	}
	return HeapReAlloc(crtHeap, 0, p, size);
}

static void *hookRecalloc(void *p, size_t count, size_t size)
{
	if (!p) {
		return hookCalloc(count, size);
	}
	if (size && count > SIZE_MAX / size) {
		return NULL;
	}
	size *= count;
	if (size == 0) {
		hookFree(p);
		return NULL;
	}
	if (size <= 8) {
		size = 16;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_recalloc(p, 1, size);
	}
	return HeapReAlloc(crtHeap, HEAP_ZERO_MEMORY, p, size);
}

static void *hookExpand(void *p, size_t size)
{
	if (!p) {
		return NULL;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_expand(p, size);
	}
	return HeapReAlloc(crtHeap, HEAP_REALLOC_IN_PLACE_ONLY, p, size);
}

static void *foreignAlignedBase(void *p)
{
	return *(void **)(((uintptr_t)p - sizeof(void *)) & ~(sizeof(void *) - 1));
}

static void *hookAlignedOffsetMalloc(size_t size, size_t align, size_t offset)
{
	return mi_malloc_aligned_at(size, align, offset);
}

static void *hookAlignedMalloc(size_t size, size_t align)
{
	return mi_malloc_aligned_at(size, align, 0);
}

static void hookAlignedFree(void *p)
{
	if (!p) {
		return;
	}
	if (mi_is_in_heap_region(p)) {
		mi_free(p);
	} else {
		HeapFree(crtHeap, 0, foreignAlignedBase(p));
	}
}

static size_t foreignAlignedSize(void *p, size_t align)
{
	void *base = foreignAlignedBase(p);
	size_t total = HeapSize(crtHeap, 0, base);
	size_t room = total - (size_t)((char *)p - (char *)base);
	if (align < sizeof(void *)) {
		align = sizeof(void *);
	}
	if (total < align + sizeof(void *)) {
		return 0;
	}
	total -= align + sizeof(void *);
	return total < room ? total : room;
}

static size_t hookAlignedMsize(void *p, size_t align, size_t offset)
{
	if (!p) {
		return (size_t)-1;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_usable_size(p);
	}
	return foreignAlignedSize(p, align);
}

static void *moveForeignAligned(void *p, void *fresh, size_t size, size_t align)
{
	size_t oldSize;
	if (!fresh) {
		return NULL;
	}
	oldSize = foreignAlignedSize(p, align);
	memcpy(fresh, p, oldSize < size ? oldSize : size);
	HeapFree(crtHeap, 0, foreignAlignedBase(p));
	return fresh;
}

static void *hookAlignedOffsetRealloc(void *p, size_t size, size_t align, size_t offset)
{
	if (!p) {
		return mi_malloc_aligned_at(size, align, offset);
	}
	if (size == 0) {
		hookAlignedFree(p);
		return NULL;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_realloc_aligned_at(p, size, align, offset);
	}
	return moveForeignAligned(p, mi_malloc_aligned_at(size, align, offset), size, align);
}

static void *hookAlignedRealloc(void *p, size_t size, size_t align)
{
	return hookAlignedOffsetRealloc(p, size, align, 0);
}

static void *hookAlignedOffsetRecalloc(void *p, size_t count, size_t size, size_t align, size_t offset)
{
	if (size && count > SIZE_MAX / size) {
		return NULL;
	}
	if (!p) {
		return mi_zalloc_aligned_at(count * size, align, offset);
	}
	if (count * size == 0) {
		hookAlignedFree(p);
		return NULL;
	}
	if (mi_is_in_heap_region(p)) {
		return mi_recalloc_aligned_at(p, count, size, align, offset);
	}
	return moveForeignAligned(p, mi_zalloc_aligned_at(count * size, align, offset), count * size, align);
}

static void *hookAlignedRecalloc(void *p, size_t count, size_t size, size_t align)
{
	return hookAlignedOffsetRecalloc(p, count, size, align, 0);
}

static unsigned char *allocNear(unsigned char *site)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	for (uintptr_t d = 0x1000000; d < 0x70000000; d += si.dwAllocationGranularity) {
		unsigned char *m = VirtualAlloc(site - d, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (m) {
			return m;
		}
		m = VirtualAlloc(site + d, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (m) {
			return m;
		}
	}
	return NULL;
}

static int prepare(HMODULE crt, const char *name, void *hook, size_t guard)
{
	unsigned char *site = (unsigned char *)GetProcAddress(crt, name);
	if (!site || patchCount == sizeof(patches) / sizeof(patches[0])) {
		return 0;
	}
	if (!stubPage) {
		stubPage = allocNear(site);
	}
	if (!stubPage || (intptr_t)(stubPage - site) > 0x7fff0000 || (intptr_t)(site - stubPage) > 0x7fff0000) {
		return 0;
	}
	unsigned char *stub = stubPage + stubUsed;
	stubUsed += 16;
	stub[0] = 0x48;
	stub[1] = 0xb8;
	memcpy(stub + 2, &hook, 8);
	stub[10] = 0xff;
	stub[11] = 0xe0;
	patches[patchCount].site = site;
	patches[patchCount].stub = stub;
	patches[patchCount].guard = guard;
	memcpy(patches[patchCount].saved, site, 5);
	patchCount++;
	return 1;
}

static int ripInPatch(uintptr_t rip)
{
	for (int i = 0; i < patchCount; i++) {
		uintptr_t site = (uintptr_t)patches[i].site;
		if (rip >= site && rip < site + patches[i].guard) {
			return 1;
		}
	}
	return 0;
}

static int suspendOthers(void)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te;
	DWORD pid = GetCurrentProcessId();
	DWORD me = GetCurrentThreadId();
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}
	te.dwSize = sizeof(te);
	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID == pid && te.th32ThreadID != me && threadCount < 256) {
				HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
				if (h) {
					threadHandles[threadCount++] = h;
				}
			}
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);
	for (int i = 0; i < threadCount; i++) {
		for (int tries = 0; tries < 100; tries++) {
			CONTEXT ctx;
			SuspendThread(threadHandles[i]);
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(threadHandles[i], &ctx) || !ripInPatch(ctx.Rip)) {
				break;
			}
			ResumeThread(threadHandles[i]);
			Sleep(0);
		}
	}
	return 1;
}

static void resumeOthers(void)
{
	for (int i = 0; i < threadCount; i++) {
		ResumeThread(threadHandles[i]);
		CloseHandle(threadHandles[i]);
	}
	threadCount = 0;
}

static int writeSite(unsigned char *site, const unsigned char *bytes)
{
	DWORD old;
	if (!VirtualProtect(site, 8, PAGE_EXECUTE_READWRITE, &old)) {
		return 0;
	}
	if (((uintptr_t)site & 7) == 0) {
		unsigned char qword[8];
		LONG64 value;
		memcpy(qword, site, 8);
		memcpy(qword, bytes, 5);
		memcpy(&value, qword, 8);
		InterlockedExchange64((volatile LONG64 *)site, value);
	} else {
		memcpy(site, bytes, 5);
	}
	VirtualProtect(site, 8, old, &old);
	FlushInstructionCache(GetCurrentProcess(), site, 8);
	return 1;
}

static void install(void)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	HMODULE crt = GetModuleHandleA("ucrtbase.dll");
	HANDLE (*getHeapHandle)(void);
	unsigned char *crtMalloc;
	if (!ntdll || !crt || !GetProcAddress(ntdll, "wine_get_version") || mi_teb_slot == TLS_OUT_OF_INDEXES) {
		return;
	}
	crtMalloc = (unsigned char *)GetProcAddress(crt, "malloc");
	if (!crtMalloc || crtMalloc[0] == 0xe9 || crtMalloc[0] == 0xeb) {
		return;
	}
	getHeapHandle = (HANDLE (*)(void))GetProcAddress(crt, "_get_heap_handle");
	if (!getHeapHandle) {
		return;
	}
	crtHeap = getHeapHandle();
	mi_free(mi_malloc(16));
	int ok = prepare(crt, "malloc", (void *)hookMalloc, 5)
		& prepare(crt, "calloc", (void *)hookCalloc, 5)
		& prepare(crt, "realloc", (void *)hookRealloc, 5)
		& prepare(crt, "free", (void *)hookFree, 5)
		& prepare(crt, "_msize", (void *)hookMsize, 5)
		& prepare(crt, "_recalloc", (void *)hookRecalloc, 5)
		& prepare(crt, "_expand", (void *)hookExpand, 5)
		& prepare(crt, "_malloc_base", (void *)hookMalloc, 5)
		& prepare(crt, "_calloc_base", (void *)hookCalloc, 5)
		& prepare(crt, "_realloc_base", (void *)hookRealloc, 5)
		& prepare(crt, "_free_base", (void *)hookFree, 5)
		& prepare(crt, "_aligned_malloc", (void *)hookAlignedMalloc, 5)
		& prepare(crt, "_aligned_offset_malloc", (void *)hookAlignedOffsetMalloc, 256)
		& prepare(crt, "_aligned_realloc", (void *)hookAlignedRealloc, 5)
		& prepare(crt, "_aligned_offset_realloc", (void *)hookAlignedOffsetRealloc, 5)
		& prepare(crt, "_aligned_recalloc", (void *)hookAlignedRecalloc, 5)
		& prepare(crt, "_aligned_offset_recalloc", (void *)hookAlignedOffsetRecalloc, 5)
		& prepare(crt, "_aligned_msize", (void *)hookAlignedMsize, 5)
		& prepare(crt, "_aligned_free", (void *)hookAlignedFree, 5);
	if (!ok || !suspendOthers()) {
		patchCount = 0;
		return;
	}
	for (int i = 0; i < patchCount; i++) {
		unsigned char jmp[5];
		int32_t rel = (int32_t)(patches[i].stub - (patches[i].site + 5));
		jmp[0] = 0xe9;
		memcpy(jmp + 1, &rel, 4);
		if (!writeSite(patches[i].site, jmp)) {
			while (i-- > 0) {
				writeSite(patches[i].site, patches[i].saved);
			}
			patchCount = 0;
			break;
		}
	}
	resumeOthers();
}

static void restore(void)
{
	if (!patchCount || !suspendOthers()) {
		return;
	}
	for (int i = 0; i < patchCount; i++) {
		writeSite(patches[i].site, patches[i].saved);
	}
	patchCount = 0;
	resumeOthers();
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	HMODULE self;
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(instance);
		GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)&install, &self);
		install();
	} else if (reason == DLL_PROCESS_DETACH && !reserved) {
		restore();
	}
	return TRUE;
}
