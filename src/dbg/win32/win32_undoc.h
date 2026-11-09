
#ifndef WIN32_UNDOC_H
#define WIN32_UNDOC_H

// Definitions for Windows DDK and other undocumented MS Windows types.
// Instead of requiring a DDK and NDK, we just use this file.

//---------------------------------------------------------------------------
// WinDDK types

struct UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWCH   Buffer;
};
typedef UNICODE_STRING *PUNICODE_STRING;

extern "C" char _RTL_CONSTANT_STRING_type_check(const WCHAR *s);
// __typeof would be desirable here instead of sizeof.
template <size_t N> class _RTL_CONSTANT_STRING_remove_const_template_class;
template <> class _RTL_CONSTANT_STRING_remove_const_template_class<sizeof(char)>
{
public:
  typedef char T;
};
template <> class _RTL_CONSTANT_STRING_remove_const_template_class<sizeof(WCHAR)>
{
public:
  typedef WCHAR T;
};
#define _RTL_CONSTANT_STRING_remove_const_macro(s) \
  (const_cast<_RTL_CONSTANT_STRING_remove_const_template_class<sizeof((s)[0])>::T*>(s))

#define RTL_CONSTANT_STRING(s) \
{ \
  sizeof(s) - sizeof((s)[0]), \
  sizeof(s) / sizeof(_RTL_CONSTANT_STRING_type_check(s)), \
  _RTL_CONSTANT_STRING_remove_const_macro(s) \
}

typedef struct _OBJECT_ATTRIBUTES64
{
  ULONG Length;
  ULONG64 RootDirectory;
  ULONG64 ObjectName;
  ULONG Attributes;
  ULONG64 SecurityDescriptor;
  ULONG64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64 *POBJECT_ATTRIBUTES64;
typedef CONST OBJECT_ATTRIBUTES64 *PCOBJECT_ATTRIBUTES64;

typedef struct _OBJECT_ATTRIBUTES32
{
  ULONG Length;
  ULONG RootDirectory;
  ULONG ObjectName;
  ULONG Attributes;
  ULONG SecurityDescriptor;
  ULONG SecurityQualityOfService;
} OBJECT_ATTRIBUTES32;
typedef OBJECT_ATTRIBUTES32 *POBJECT_ATTRIBUTES32;
typedef CONST OBJECT_ATTRIBUTES32 *PCOBJECT_ATTRIBUTES32;

typedef struct _OBJECT_ATTRIBUTES
{
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
  PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p,n,a,r,s) \
{                                             \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES);    \
  (p)->RootDirectory = (r);                   \
  (p)->Attributes = (a);                      \
  (p)->ObjectName = (n);                      \
  (p)->SecurityDescriptor = (s);              \
  (p)->SecurityQualityOfService = nullptr;       \
}

//
// Definitions for Object Creation
//
#define OBJ_INHERIT                             0x00000002
#define OBJ_PERMANENT                           0x00000010
#define OBJ_EXCLUSIVE                           0x00000020
#define OBJ_CASE_INSENSITIVE                    0x00000040
#define OBJ_OPENIF                              0x00000080
#define OBJ_OPENLINK                            0x00000100
#define OBJ_KERNEL_HANDLE                       0x00000200
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400
#define OBJ_VALID_ATTRIBUTES                    0x000007F2

//---------------------------------------------------------------------------
// Undocumented types - pulled out of MS Windows NDK by Alex Ionecsu

//
// Privilege constants
//
#define SE_MIN_WELL_KNOWN_PRIVILEGE       2
#define SE_CREATE_TOKEN_PRIVILEGE         2
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE   3
#define SE_LOCK_MEMORY_PRIVILEGE          4
#define SE_INCREASE_QUOTA_PRIVILEGE       5
#define SE_UNSOLICITED_INPUT_PRIVILEGE    6
#define SE_MACHINE_ACCOUNT_PRIVILEGE      6
#define SE_TCB_PRIVILEGE                  7
#define SE_SECURITY_PRIVILEGE             8
#define SE_TAKE_OWNERSHIP_PRIVILEGE       9
#define SE_LOAD_DRIVER_PRIVILEGE          10
#define SE_SYSTEM_PROFILE_PRIVILEGE       11
#define SE_SYSTEMTIME_PRIVILEGE           12
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  13
#define SE_INC_BASE_PRIORITY_PRIVILEGE    14
#define SE_CREATE_PAGEFILE_PRIVILEGE      15
#define SE_CREATE_PERMANENT_PRIVILEGE     16
#define SE_BACKUP_PRIVILEGE               17
#define SE_RESTORE_PRIVILEGE              18
#define SE_SHUTDOWN_PRIVILEGE             19
#define SE_DEBUG_PRIVILEGE                20
#define SE_AUDIT_PRIVILEGE                21
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   22
#define SE_CHANGE_NOTIFY_PRIVILEGE        23
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      24
#define SE_MAX_WELL_KNOWN_PRIVILEGE       SE_REMOTE_SHUTDOWN_PRIVILEGE


// Undocumented NTSystemDebugControl function (to read/write MSRs)
enum SYSDBG_COMMAND
{
  SysDbgQueryModuleInformation = 1,
  SysDbgQueryTraceInformation  = 2,
  SysDbgSetTracepoint          = 3,
  SysDbgSetSpecialCall         = 4,
  SysDbgClearSpecialCalls      = 5,
  SysDbgQuerySpecialCalls      = 6,
  SysDbgReadMsr                = 16,
  SysDbgWriteMsr               = 17,
};

struct SYSDBG_MSR
{
  uint32 reg;
  uint32 padding;
  uint64 value;
};
#define NTSTATUS int
#ifndef NTAPI
#define NTAPI WINAPI
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED          0xC0000002
#endif

#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED     0xC000010E
#endif

//
// NtCreateFile OpenType Flags
//
#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

//
// NtCreateFile Flags
//
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080
#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

//
// Interface for communicating with private WinDBG interface
//
#define KLDD_CODE_DEBUG_CONTROL                 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_NEITHER, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _KLDD_DATA_DEBUG_CONTROL
{
  SYSDBG_COMMAND Command;
  PVOID InputBuffer;
  SIZE_T InputBufferLength;
} KLDD_DATA_DEBUG_CONTROL, *PKLDD_DATA_DEBUG_CONTROL;

//
// I/O Status Block
//
typedef struct _IO_STATUS_BLOCK
{
  union
  {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//
// APC Callback for NtDeviceIoControlFile
//
typedef VOID
(NTAPI *PIO_APC_ROUTINE)(
        IN PVOID ApcContext,
        IN PIO_STATUS_BLOCK IoStatusBlock,
        IN ULONG Reserved);

typedef NTSTATUS NTAPI NtSystemDebugControl_t(
        IN SYSDBG_COMMAND Command,
        IN PVOID InputBuffer OPTIONAL,
        IN ULONG InputBufferLength,
        OUT PVOID OutputBuffer OPTIONAL,
        IN ULONG OutputBufferLength,
        OUT PULONG ReturnLength OPTIONAL);

typedef NTSTATUS NTAPI NtLoadDriver_t(
        IN PUNICODE_STRING DriverServiceName);

typedef NTSTATUS NTAPI NtUnloadDriver_t(
        IN PUNICODE_STRING DriverServiceName);

typedef NTSTATUS NTAPI RtlAdjustPrivilege_t(
        IN ULONG Privilege,
        IN BOOLEAN NewValue,
        IN BOOLEAN ForThread,
        OUT PBOOLEAN OldValue);

typedef NTSTATUS NTAPI NtCreateFile_t(
        OUT PHANDLE FileHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN PLARGE_INTEGER AllocationSize OPTIONAL,
        IN ULONG FileAttributes,
        IN ULONG ShareAccess,
        IN ULONG CreateDisposition,
        IN ULONG CreateOptions,
        IN PVOID EaBuffer OPTIONAL,
        IN ULONG EaLength);

typedef NTSTATUS NTAPI NtDeviceIoControlFile_t(
        IN HANDLE DeviceHandle,
        IN HANDLE Event OPTIONAL,
        IN PIO_APC_ROUTINE UserApcRoutine OPTIONAL,
        IN PVOID UserApcContext OPTIONAL,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
        IN ULONG IoControlCode,
        IN PVOID InputBuffer,
        IN ULONG InputBufferSize,
        OUT PVOID OutputBuffer,
        IN ULONG OutputBufferSize);

#endif // define WIN32_UNDOC_H
