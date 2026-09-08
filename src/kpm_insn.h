#ifndef _KPM_INSN_H_
#define _KPM_INSN_H_

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/printk.h>

enum kpm_insn_imm_type {
	KPM_INSN_IMM_ADR,
	KPM_INSN_IMM_26,
	KPM_INSN_IMM_19,
	KPM_INSN_IMM_16,
	KPM_INSN_IMM_14,
	KPM_INSN_IMM_12,
	KPM_INSN_IMM_9,
	KPM_INSN_IMM_7,
	KPM_INSN_IMM_6,
	KPM_INSN_IMM_S,
	KPM_INSN_IMM_R,
	KPM_INSN_IMM_MAX,
};

static inline u32 kpm_aarch64_insn_encode_immediate(enum kpm_insn_imm_type type, u32 insn, u64 imm)
{
	u32 immlo, immhi, lomask, himask, mask;
	int shift;

	switch (type) {
	case KPM_INSN_IMM_ADR:
		lomask = 0x3;
		himask = 0x7ffff;
		immlo = imm & lomask;
		imm >>= 2;
		immhi = imm & himask;
		imm = (immlo << 24) | immhi;
		mask = (lomask << 24) | himask;
		shift = 5;
		break;
	case KPM_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case KPM_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case KPM_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case KPM_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case KPM_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case KPM_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case KPM_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case KPM_INSN_IMM_6:
	case KPM_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case KPM_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	default:
		pr_err("aarch64_insn_encode_immediate: unknown immediate encoding %d\n", type);
		return 0;
	}

	insn &= ~(mask << shift);
	insn |= (imm & mask) << shift;

	return insn;
}

#define KPM_AARCH64_IMM_MOVNZ KPM_INSN_IMM_MAX
#define KPM_AARCH64_IMM_MOVK KPM_INSN_IMM_16

#define KPM_BIT(nr) (1UL << (nr))

enum kpm_aarch64_reloc_op {
	KPM_RELOC_OP_NONE,
	KPM_RELOC_OP_ABS,
	KPM_RELOC_OP_PREL,
	KPM_RELOC_OP_PAGE,
};

#endif /* _KPM_INSN_H_ */