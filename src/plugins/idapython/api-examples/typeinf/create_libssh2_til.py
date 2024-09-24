"""
summary: Programatically create a til file.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
     * We create a new libssh2-64.til file where we load some libssh2
      64-bit structures.
     * Once the file has been created, it can copied in the IDA install
     til directory or in the user IDA til directory.
"""
import ida_typeinf
import ida_kernwin

libssh2_types = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef __int64 size_t;

struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
{
    unsigned char *text;
    size_t length;
    unsigned char echo;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_PROMPT LIBSSH2_USERAUTH_KBDINT_PROMPT;

struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
{
    char *text;
    unsigned int length;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE LIBSSH2_USERAUTH_KBDINT_RESPONSE;

struct _LIBSSH2_SK_SIG_INFO {
    uint8_t flags;
    uint32_t counter;
    unsigned char *sig_r;
    size_t sig_r_len;
    unsigned char *sig_s;
    size_t sig_s_len;
};
typedef struct _LIBSSH2_SK_SIG_INFO LIBSSH2_SK_SIG_INFO;

"""


def add_types():
    # Create a new til file.
    t = ida_typeinf.new_til("libssh2-64.til", "Few libssh2 types")
    # Parse the declaratiion, ignoring redeclaration warnings and applying default packing/
    if ida_typeinf.parse_decls(t, libssh2_types, None, ida_typeinf.HTI_DCL | ida_typeinf.HTI_PAKDEF):
        ida_kernwin.msg('Failed to parse the libssh2 declarations.\n')
        return
    ida_typeinf.compact_til(t)
    # The til file will be saved in the current working directory.
    if ida_typeinf.store_til(t, None, "libssh2-64.til"):
        ida_kernwin.msg("TIL file stored on disk.\n")
    ida_typeinf.free_til(t)

if __name__ == "__main__":
    add_types()
