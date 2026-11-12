/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Block framing for the OTi-2208 bridge, shared by the kernel driver and the
 * frame-compatibility test (test/frame_compat.c, which builds this header in
 * userspace with small stand-ins for the unaligned helpers).
 * The format must stay byte-compatible with prototype/oti2208-bridge.c.
 */
#ifndef OTI2208_FRAME_H
#define OTI2208_FRAME_H

/* block format */
#define OTI_BLOCK_SIZE		0x10000u
#define OTI_HDR_SIZE		20u
#define OTI_TRAILER_OFF		(OTI_BLOCK_SIZE - OTI_HDR_SIZE)
#define OTI_PAYLOAD_OFF		OTI_HDR_SIZE
#define OTI_PAYLOAD_MAX		(OTI_TRAILER_OFF - OTI_PAYLOAD_OFF)
#define OTI_FRAME_HDR		2u
#define OTI_FRAME_MAX		(OTI_PAYLOAD_MAX - OTI_FRAME_HDR)
#define OTI_BLK_MAGIC		0x4E45544Fu	/* "OTEN" */
#define OTI_BLK_VERSION		2u	/* 2: no CRC; offset 16 is reserved (0) */
#define OTI_BF_MORE			0x01u

static void blk_finish(u8 *blk, u32 seq, u16 nframes, u32 used, u8 flags)
{
	put_unaligned_le32(OTI_BLK_MAGIC, blk);
	put_unaligned_le32(seq, blk + 4);
	put_unaligned_le16(nframes, blk + 8);
	blk[10] = OTI_BLK_VERSION;
	blk[11] = flags;
	put_unaligned_le32(used, blk + 12);
	put_unaligned_le32(0, blk + 16);	/* reserved */
	memcpy(blk + OTI_TRAILER_OFF, blk, OTI_HDR_SIZE);
}

/* Validate a received block. Returns nframes (>= 0), or -1 if invalid. */
static int blk_check(const u8 *blk, u32 len)
{
	static const u8 zero[OTI_HDR_SIZE];
	u32 plen, off = 0;
	u16 n, i;

	if (len != OTI_BLOCK_SIZE || !memcmp(blk, zero, OTI_HDR_SIZE))
		return -1;
	if (memcmp(blk, blk + OTI_TRAILER_OFF, OTI_HDR_SIZE))
		return -1;
	if (get_unaligned_le32(blk) != OTI_BLK_MAGIC || blk[10] != OTI_BLK_VERSION)
		return -1;
	n = get_unaligned_le16(blk + 8);
	plen = get_unaligned_le32(blk + 12);
	if (plen > OTI_PAYLOAD_MAX)
		return -1;
	for (i = 0; i < n; i++) {
		u16 fl;

		if (off + OTI_FRAME_HDR > plen)
			return -1;
		fl = get_unaligned_le16(blk + OTI_PAYLOAD_OFF + off);
		if (!fl || off + OTI_FRAME_HDR + fl > plen)
			return -1;
		off += OTI_FRAME_HDR + fl;
	}
	return off == plen ? n : -1;
}

#endif /* OTI2208_FRAME_H */
