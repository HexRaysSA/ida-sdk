//
// Loader for HP-UX PA-Risc core dumps that are not ELF
//
// Avi Cohen Stuart avi.cohenstuart@infor.com
// August 2010
//
// The core image exists of sections defined by the types below
//struct corehead {
//      int     type;
//      uint    space;
//      uint    addr;
//      uint    len;
//};
//
// Analysing a core file can be tedious without the binary that
// caused the crash.
//
// Note that the CORE_PROC section contains information about the
// state of the process. See the proc_info in /usr/include/sys/core.h on
// a HP-UX PA-Risc machine.
//
#include <idc.idc>

#define CORE_NONE       0x00000000      /* reserved for future use */
#define CORE_FORMAT     0x00000001      /* core version */
#define CORE_KERNEL     0x00000002      /* kernel version */
#define CORE_PROC       0x00000004      /* per process information */
#define CORE_TEXT       0x00000008      /* reserved for future use */
#define CORE_DATA       0x00000010      /* data of the process */
#define CORE_STACK      0x00000020      /* stack of the process */
#define CORE_SHM        0x00000040      /* reserved for future use */
#define CORE_MMF        0x00000080      /* reserved for future use */
#define CORE_EXEC       0x00000100      /* exec information */
#define CORE_ANON_SHMEM 0x00000200      /* anonymous shared memory */

static Structures_0(id) {
        auto mid;

        id = add_struc(-1,"__reg32_t",0);
        id = add_struc(-1,"__reg64_t",0);
        id = add_struc(-1,"__save_state::$8C0FCFCC2B9ACB495244C4B504AA9783",1);
        id = add_struc(-1,"fp_int_block_t",0);
        id = add_struc(-1,"fp_dbl_block_t",0);
        id = add_struc(-1,"__save_state::$F0F3A0B47411777C5961C26FBCE8E4DA",1);
        id = add_struc(-1,"__ss_narrow_t",0);

        id = add_struc(-1,"save_state_t",0);
        id = add_struc(-1,"aux_id",0);
        id = add_struc(-1,"som_exec_auxhdr",0);
        id = add_struc(-1,"proc_exec::$733C094BD5627056653FFCFE6E9DB4EB",0);
        id = add_struc(-1,"proc_info",0);
        id = add_struc(-1,"shl_descriptor",0);
        id = add_struc(-1,"proc_exec",0);

        id = get_struc_id("__reg32_t");
        mid = add_struc_member(id,"ss_reserved",  0X0,    0x20000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr1_hi",    0X8,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr1_lo",    0XC,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_rp_hi",     0X10,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_rp_lo",     0X14,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr3_hi",    0X18,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr3_lo",    0X1C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr4_hi",    0X20,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr4_lo",    0X24,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr5_hi",    0X28,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr5_lo",    0X2C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr6_hi",    0X30,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr6_lo",    0X34,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr7_hi",    0X38,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr7_lo",    0X3C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr8_hi",    0X40,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr8_lo",    0X44,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr9_hi",    0X48,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr9_lo",    0X4C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr10_hi",   0X50,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr10_lo",   0X54,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr11_hi",   0X58,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr11_lo",   0X5C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr12_hi",   0X60,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr12_lo",   0X64,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr13_hi",   0X68,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr13_lo",   0X6C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr14_hi",   0X70,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr14_lo",   0X74,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr15_hi",   0X78,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr15_lo",   0X7C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr16_hi",   0X80,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr16_lo",   0X84,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr17_hi",   0X88,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr17_lo",   0X8C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr18_hi",   0X90,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr18_lo",   0X94,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr19_hi",   0X98,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr19_lo",   0X9C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr20_hi",   0XA0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr20_lo",   0XA4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr21_hi",   0XA8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr21_lo",   0XAC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr22_hi",   0XB0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr22_lo",   0XB4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg3_hi",   0XB8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg3_lo",   0XBC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg2_hi",   0XC0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg2_lo",   0XC4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg1_hi",   0XC8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg1_lo",   0XCC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg0_hi",   0XD0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg0_lo",   0XD4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_dp_hi",     0XD8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_dp_lo",     0XDC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_ret0_hi",   0XE0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_ret0_lo",   0XE4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_ret1_hi",   0XE8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_ret1_lo",   0XEC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sp_hi",     0XF0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sp_lo",     0XF4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr31_hi",   0XF8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr31_lo",   0XFC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr11_hi",   0X100,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr11_lo",   0X104,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_head_hi",      0X108,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_head_lo",      0X10C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_head_hi",      0X110,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_head_lo",      0X114,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_tail_hi",      0X118,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_tail_lo",      0X11C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_tail_hi",      0X120,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_tail_lo",      0X124,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr15_hi",   0X128,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr15_lo",   0X12C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr19_hi",   0X130,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr19_lo",   0X134,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr20_hi",   0X138,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr20_lo",   0X13C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr21_hi",   0X140,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr21_lo",   0X144,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr22_hi",   0X148,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr22_lo",   0X14C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cpustate_hi",       0X150,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cpustate_lo",       0X154,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr4_hi",    0X158,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr4_lo",    0X15C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr0_hi",    0X160,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr0_lo",    0X164,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr1_hi",    0X168,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr1_lo",    0X16C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr2_hi",    0X170,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr2_lo",    0X174,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr3_hi",    0X178,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr3_lo",    0X17C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr5_hi",    0X180,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr5_lo",    0X184,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr6_hi",    0X188,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr6_lo",    0X18C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr7_hi",    0X190,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr7_lo",    0X194,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr0_hi",    0X198,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr0_lo",    0X19C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr8_hi",    0X1A0,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr8_lo",    0X1A4,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr9_hi",    0X1A8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr9_lo",    0X1AC,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr10_hi",   0X1B0,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr10_lo",   0X1B4,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr12_hi",   0X1B8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr12_lo",   0X1BC,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr13_hi",   0X1C0,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr13_lo",   0X1C4,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr24_hi",   0X1C8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr24_lo",   0X1CC,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr25_hi",   0X1D0,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr25_lo",   0X1D4,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr26_hi",   0X1D8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr26_lo",   0X1DC,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr27_hi",   0X1E0,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr27_lo",   0X1E4,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_reserved2", 0X1E8,  0x20000400,     -1,     16);
        mid = add_struc_member(id,"ss_oldcksum",  0X1F8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_newcksum",  0X1FC,  0x20000400,     -1,     4);

        id = get_struc_id("__reg64_t");
        mid = add_struc_member(id,"ss_reserved",  0X0,    0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr1",       0X8,    0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_rp",        0X10,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr3",       0X18,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr4",       0X20,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr5",       0X28,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr6",       0X30,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr7",       0X38,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr8",       0X40,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr9",       0X48,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr10",      0X50,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr11",      0X58,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr12",      0X60,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr13",      0X68,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr14",      0X70,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr15",      0X78,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr16",      0X80,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr17",      0X88,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr18",      0X90,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr19",      0X98,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr20",      0XA0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr21",      0XA8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr22",      0XB0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_arg3",      0XB8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_arg2",      0XC0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_arg1",      0XC8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_arg0",      0XD0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_dp",        0XD8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_ret0",      0XE0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_ret1",      0XE8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sp",        0XF0,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_gr31",      0XF8,   0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr11",      0X100,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_pcoq_head", 0X108,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_pcsq_head", 0X110,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_pcoq_tail", 0X118,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_pcsq_tail", 0X120,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr15",      0X128,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr19",      0X130,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr20",      0X138,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr21",      0X140,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr22",      0X148,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cpustate",  0X150,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr4",       0X158,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr0",       0X160,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr1",       0X168,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr2",       0X170,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr3",       0X178,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr5",       0X180,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr6",       0X188,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_sr7",       0X190,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr0",       0X198,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr8",       0X1A0,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr9",       0X1A8,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr10",      0X1B0,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr12",      0X1B8,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr13",      0X1C0,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr24",      0X1C8,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr25",      0X1D0,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr26",      0X1D8,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_cr27",      0X1E0,  0x30000400,     -1,     8);
        mid = add_struc_member(id,"ss_reserved2", 0X1E8,  0x30000400,     -1,     16);
        mid = add_struc_member(id,"ss_oldcksum",  0X1F8,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_newcksum",  0X1FC,  0x20000400,     -1,     4);

        id = get_struc_id("__save_state::$8C0FCFCC2B9ACB495244C4B504AA9783");
        mid = add_struc_member(id,"ss_64",        0X0,    0x60000400,     get_struc_id("__reg64_t"),  512);
        mid = add_struc_member(id,"ss_32",        0X0,    0x60000400,     get_struc_id("__reg32_t"),  512);

        id = get_struc_id("fp_int_block_t");
        mid = add_struc_member(id,"ss_fpstat",    0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept1", 0X4,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept2", 0X8,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept3", 0XC,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept4", 0X10,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept5", 0X14,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept6", 0X18,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpexcept7", 0X1C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp4_hi",    0X20,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp4_lo",    0X24,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp5_hi",    0X28,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp5_lo",    0X2C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp6_hi",    0X30,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp6_lo",    0X34,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp7_hi",    0X38,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp7_lo",    0X3C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp8_hi",    0X40,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp8_lo",    0X44,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp9_hi",    0X48,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp9_lo",    0X4C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp10_hi",   0X50,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp10_lo",   0X54,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp11_hi",   0X58,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp11_lo",   0X5C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp12_hi",   0X60,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp12_lo",   0X64,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp13_hi",   0X68,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp13_lo",   0X6C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp14_hi",   0X70,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp14_lo",   0X74,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp15_hi",   0X78,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp15_lo",   0X7C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp16_hi",   0X80,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp16_lo",   0X84,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp17_hi",   0X88,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp17_lo",   0X8C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp18_hi",   0X90,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp18_lo",   0X94,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp19_hi",   0X98,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp19_lo",   0X9C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp20_hi",   0XA0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp20_lo",   0XA4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp21_hi",   0XA8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp21_lo",   0XAC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp22_hi",   0XB0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp22_lo",   0XB4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp23_hi",   0XB8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp23_lo",   0XBC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp24_hi",   0XC0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp24_lo",   0XC4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp25_hi",   0XC8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp25_lo",   0XCC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp26_hi",   0XD0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp26_lo",   0XD4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp27_hi",   0XD8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp27_lo",   0XDC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp28_hi",   0XE0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp28_lo",   0XE4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp29_hi",   0XE8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp29_lo",   0XEC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp30_hi",   0XF0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp30_lo",   0XF4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp31_hi",   0XF8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fp31_lo",   0XFC,   0x20000400,     -1,     4);

        id = get_struc_id("fp_dbl_block_t");
        mid = add_struc_member(id,"ss_fp0",       0X0,    0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp1",       0X8,    0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp2",       0X10,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp3",       0X18,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp4",       0X20,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp5",       0X28,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp6",       0X30,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp7",       0X38,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp8",       0X40,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp9",       0X48,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp10",      0X50,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp11",      0X58,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp12",      0X60,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp13",      0X68,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp14",      0X70,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp15",      0X78,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp16",      0X80,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp17",      0X88,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp18",      0X90,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp19",      0X98,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp20",      0XA0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp21",      0XA8,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp22",      0XB0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp23",      0XB8,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp24",      0XC0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp25",      0XC8,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp26",      0XD0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp27",      0XD8,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp28",      0XE0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp29",      0XE8,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp30",      0XF0,   0x90000400,     -1,     8);
        mid = add_struc_member(id,"ss_fp31",      0XF8,   0x90000400,     -1,     8);

        id = get_struc_id("__save_state::$F0F3A0B47411777C5961C26FBCE8E4DA");
        mid = add_struc_member(id,"fpdbl",        0X0,    0x60000400,     get_struc_id("fp_dbl_block_t"),     256);
        mid = add_struc_member(id,"fpint",        0X0,    0x60000400,     get_struc_id("fp_int_block_t"),     256);

        id = get_struc_id("__ss_narrow_t");
        mid = add_struc_member(id,"ss_gr1",       0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_rp",        0X4,    0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_gr3",       0X8,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr4",       0XC,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr5",       0X10,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr6",       0X14,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr7",       0X18,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr8",       0X1C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr9",       0X20,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr10",      0X24,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr11",      0X28,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr12",      0X2C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr13",      0X30,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr14",      0X34,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr15",      0X38,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr16",      0X3C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr17",      0X40,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr18",      0X44,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr19",      0X48,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr20",      0X4C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr21",      0X50,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_gr22",      0X54,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_arg3",      0X58,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_arg2",      0X5C,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_arg1",      0X60,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_arg0",      0X64,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_dp",        0X68,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_ret0",      0X6C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_ret1",      0X70,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sp",        0X74,   0x20500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ss_gr31",      0X78,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr11",      0X7C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_head", 0X80,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_head", 0X84,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcoq_tail", 0X88,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_pcsq_tail", 0X8C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr15",      0X90,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr19",      0X94,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr20",      0X98,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr21",      0X9C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr22",      0XA0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cpustate",  0XA4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr4",       0XA8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr0",       0XAC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr1",       0XB0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr2",       0XB4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr3",       0XB8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr5",       0XBC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr6",       0XC0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_sr7",       0XC4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr0",       0XC8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr8",       0XCC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr9",       0XD0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr10",      0XD4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr12",      0XD8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr13",      0XDC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr24",      0XE0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr25",      0XE4,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr26",      0XE8,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_cr27",      0XEC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_mpsfu_low", 0XF0,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_mpsfu_ovflo",       0XF4,   0x20000400,     -1,     4);

        id = get_struc_id("save_state_t");
        mid = add_struc_member(id,"ss_flags",     0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_narrow",    0X4,    0x60000400,     get_struc_id("__ss_narrow_t"),      248);
        mid = add_struc_member(id,"ss_pad",       0XFC,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"ss_fpblock",   0X100,  0x60000400,     get_struc_id("__save_state::$F0F3A0B47411777C5961C26FBCE8E4DA"),    256);
        mid = add_struc_member(id,"ss_xor",       0X200,  0x000400,       -1,     128);
        mid = add_struc_member(id,"ss_wide",      0X280,  0x60000400,     get_struc_id("__save_state::$8C0FCFCC2B9ACB495244C4B504AA9783"),    512);

        id = get_struc_id("proc_info");
        mid = add_struc_member(id,"sig",  0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"trap_type",    0X4,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"hw_regs",      0X8,    0x60000400,     get_struc_id("save_state_t"),       1152);
        mid = add_struc_member(id,"lwpid",        0X488,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"user_tid",     0X48C,  0x30000400,     -1,     8);

        id = get_struc_id("shl_descriptor");
        mid = add_struc_member(id,"tstart",       0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"tend", 0X4,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"dstart",       0X8,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"dend", 0XC,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"ltptr",        0X10,   0x25500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"handle",       0X14,   0x25500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"filename",     0X18,   0x50000400,     0x0,    1025);
        mid = add_struc_member(id,"initializer",  0X41C,  0x25500400,     BADADDR,     4,      BADADDR,     0X0,    0x000002);
        mid = add_struc_member(id,"ref_count",    0X420,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"reserved3",    0X424,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"reserved2",    0X428,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"reserved1",    0X42C,  0x20000400,     -1,     4);
        mid = add_struc_member(id,"reserved0",    0X430,  0x20000400,     -1,     4);

        id = get_struc_id("aux_id");
        mid = add_struc_member(id,"type", 0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"length",       0X4,    0x20000400,     -1,     4);

        id = get_struc_id("som_exec_auxhdr");
        mid = add_struc_member(id,"som_auxhdr",   0X0,    0x60000400,     get_struc_id("aux_id"),     8);
        mid = add_struc_member(id,"exec_tsize",   0X8,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_tmem",    0XC,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_tfile",   0X10,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_dsize",   0X14,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_dmem",    0X18,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_dfile",   0X1C,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_bsize",   0X20,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_entry",   0X24,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_flags",   0X28,   0x20000400,     -1,     4);
        mid = add_struc_member(id,"exec_bfill",   0X2C,   0x20000400,     -1,     4);

        id = get_struc_id("proc_exec::$733C094BD5627056653FFCFE6E9DB4EB");
        mid = add_struc_member(id,"u_magic",      0X0,    0x20000400,     -1,     4);
        mid = add_struc_member(id,"som_aux",      0X4,    0x60000400,     get_struc_id("som_exec_auxhdr"),    48);

        id = get_struc_id("proc_exec");
        mid = add_struc_member(id,"exdata",       0X0,    0x60000400,     get_struc_id("proc_exec::$733C094BD5627056653FFCFE6E9DB4EB"),       52);
        mid = add_struc_member(id,"cmd",          0X34,   0x50000400,    0x0,    15);
        mid = add_struc_member(id,"_padding",     0X43,   0x000400,       -1,     1);


        return id;
}

//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;
        id = Structures_0(id);
}

// End of file.

static accept_file(li, filename)
{
        auto buf;

        li.seek(16,0); // skip first header
        li.read(&buf, 6);

        // Magic:
        if (buf != "HP-UX\0")
          return 0;
        return "HP-UX HP-PA Core dump Image (non ELF)";
}

static read_core_head(li)
{
        auto    core_type;
        auto    core_space;
        auto    core_addr;
        auto    core_len;

        auto    proc_info_addr;
        auto    proc_exec_addr;
        auto    proc_exec_sel;

        proc_info_addr = 0;
        proc_exec_addr = 0;
        proc_exec_sel = 0;

        auto ret;
        auto mf = (get_inf_attr(INF_LFLAGS) & LFLG_MSF) != 0;
        li.seek(0, 0);
        ret = 0;
        // keep reading corehead structs and process them
        while (1) {
                ret = li.readbytes(&core_type, 4, mf);
                if (ret!=0) break;
                //msg("ret: %d\n", ret);

                ret = li.readbytes(&core_space, 4, mf);
                ret= li.readbytes(&core_addr, 4, mf);
                ret= li.readbytes(&core_len, 4, mf);

                //msg("type %x addr %x len %x\n", core_type, core_addr, core_len);

                loadfile(li, li.tell(), core_addr, core_len);

                AddSeg(core_addr, core_addr+core_len, 0, 1, saRelPara, 2);
                if (core_type==CORE_FORMAT) {
                        set_segm_class(core_addr, "FORMAT");
                        set_segm_type(core_addr, SEG_DATA);
                }
                if (core_type==CORE_PROC) {
                        set_segm_class(core_addr, "PROC");
                        set_segm_type(core_addr, SEG_DATA);
                        proc_info_addr = core_addr;
                }
                if (core_type==CORE_DATA) {
                        set_segm_class(core_addr, "DATA");
                        set_segm_type(core_addr, SEG_DATA);

                }
                if (core_type==CORE_STACK) {
                        set_segm_class(core_addr, "STACK");
                        set_segm_type(core_addr, SEG_DATA);
                }
                if (core_type==CORE_MMF) {
                        set_segm_class(core_addr, "MMF");
                }
                if (core_type==CORE_NONE) {
                        set_segm_class(core_addr, "NONE");
                }
                if (core_type==CORE_EXEC) {
                        set_segm_class(core_addr, "EXEC");
                        set_segm_type(core_addr, SEG_DATA);
                        proc_exec_addr = core_addr;
                        proc_exec_sel = get_segm_attr(core_addr, SEGATTR_SEL);
                }
        }

        set_inf_attr(INF_COMPILER, COMP_GNU); // closest to HP compiler
        set_inf_attr(INF_SIZEOF_ALGN, 4);

        Structures();

        if (proc_info_addr !=0) {
                //provide sime initial information about
                //the process state
                msg("set proc_data\n");
                create_struct(proc_info_addr, -1, "proc_info");
        }
        if (proc_exec_addr !=0) {
                // provide some info about the exec
                create_struct(proc_exec_addr, -1 , "proc_exec");
                set_inf_attr(INF_START_IP, proc_exec_addr);
                set_inf_attr(INF_START_CS, proc_exec_sel);
        }

        //
        // from here on, in a future version: locate the binary,
        // shared libraries and load them as well into the idb...
}

static load_file(li, neflags, format)
{
        set_processor_type("hppa", SETPROC_LOADER);
        set_flag(INF_LFLAGS, LFLG_PC_FLAT, 1); // 32-bit mode

        msg("file size %d\n", li.size());

        read_core_head(li);

        return 1;
}
