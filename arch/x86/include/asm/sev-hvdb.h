/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV-SNP #HV DoorBell Support
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef _ASM_SEV_HVDB_H
#define _ASM_SEV_HVDB_H

#ifndef __ASSEMBLY__

struct pt_regs;

#ifdef CONFIG_AMD_MEM_ENCRYPT
void snp_handle_pending_hvdb(struct pt_regs *regs);
#else
static inline void snp_handle_pending_hvdb(struct pt_regs *regs) { }
#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_SEV_HVDB_H */
