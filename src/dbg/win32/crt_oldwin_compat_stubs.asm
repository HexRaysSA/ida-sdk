; Old Windows compatibility: import redirections for Vista+ dependencies.
; These symbols override the linker's default resolution to import libs,
; redirecting to our C stubs in crt_oldwin_compat_stubs.cpp which do
; runtime detection and fall back to older APIs if needed.

.386
.model flat

; Fallback implementations in crt_oldwin_compat_stubs.cpp
EXTERNDEF _CompatInitializeCriticalSectionEx@12:PROC
EXTERNDEF _CompatFlsAlloc@4:PROC
EXTERNDEF _CompatFlsFree@4:PROC
EXTERNDEF _CompatFlsGetValue@4:PROC
EXTERNDEF _CompatFlsSetValue@8:PROC
EXTERNDEF _CompatDecodePointer@4:PROC
EXTERNDEF _CompatEncodePointer@4:PROC
EXTERNDEF _CompatInitializeSListHead@4:PROC
EXTERNDEF _CompatGetModuleHandleExW@12:PROC
EXTERNDEF _CompatSetFilePointerEx@20:PROC
EXTERNDEF _CompatWSAPoll@12:PROC
EXTERNDEF _CompatRegDeleteTreeA@8:PROC

.DATA

; Vista+ kernel32 APIs
PUBLIC __imp__InitializeCriticalSectionEx@12
__imp__InitializeCriticalSectionEx@12 DD _CompatInitializeCriticalSectionEx@12

PUBLIC __imp__FlsAlloc@4
__imp__FlsAlloc@4 DD _CompatFlsAlloc@4

PUBLIC __imp__FlsFree@4
__imp__FlsFree@4 DD _CompatFlsFree@4

PUBLIC __imp__FlsGetValue@4
__imp__FlsGetValue@4 DD _CompatFlsGetValue@4

PUBLIC __imp__FlsSetValue@8
__imp__FlsSetValue@8 DD _CompatFlsSetValue@8

; XP SP2+ kernel32 APIs
PUBLIC __imp__DecodePointer@4
__imp__DecodePointer@4 DD _CompatDecodePointer@4

PUBLIC __imp__EncodePointer@4
__imp__EncodePointer@4 DD _CompatEncodePointer@4

PUBLIC __imp__InitializeSListHead@4
__imp__InitializeSListHead@4 DD _CompatInitializeSListHead@4

; XP SP1+ kernel32 APIs
PUBLIC __imp__GetModuleHandleExW@12
__imp__GetModuleHandleExW@12 DD _CompatGetModuleHandleExW@12

PUBLIC __imp__SetFilePointerEx@20
__imp__SetFilePointerEx@20 DD _CompatSetFilePointerEx@20

; Vista+ ws2_32 API
PUBLIC __imp__WSAPoll@12
__imp__WSAPoll@12 DD _CompatWSAPoll@12

; Vista+ advapi32 API
PUBLIC __imp__RegDeleteTreeA@8
__imp__RegDeleteTreeA@8 DD _CompatRegDeleteTreeA@8

END
