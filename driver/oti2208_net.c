// SPDX-License-Identifier: GPL-2.0
/*
 * oti2208_net - Ethernet over the OTi-2208 "EasySuite USB Host-to-Host Data
 * Bridge" (USB 0ea0:2108).
 *
 * The cable has one chip with two USB device ports. Each host sees a USB
 * mass-storage device (Bulk-Only Transport) whose only LUN accepts vendor
 * SCSI commands. A 64 KiB block written with "D9 2A" on one side comes out
 * of "D9 28" on the other. The chip does not look at the payload, so all
 * framing is ours. The format matches prototype/oti2208-bridge.c, so this
 * driver interoperates with the userspace bridge:
 *
 *   header (20 bytes, LE), repeated at 0xFFEC:
 *     u32 magic "OTEN" | u32 seq | u16 nframes | u8 version (2) | u8 flags
 *     | u32 payload_len | u32 reserved (0)
 *   payload: [u16 len][frame]...
 *
 * There is no payload checksum (version 1 had a CRC-32): USB protects every
 * packet with a CRC-16, TCP/IP have their own checksums, and torn or stale
 * blocks are caught by the trailer copy, the frame-length walk and the
 * sequence number.
 *
 * Channel rules measured on hardware (see PROTOCOL.md §7–8):
 *  - the chip has ONE half-duplex slot. A write holds it until the peer
 *    reads; a write while the peer holds it is refused with sense 09/86
 *    after ~7 ms; a write nobody reads fails with 09/85 after ~1.3 s;
 *  - every D9 transfer must be exactly 64 KiB (shorter ones hang the chip);
 *  - D9 28 CDB[2] is the idle wait in 5 ms units (+~8 ms).
 * So the data loop takes turns. A sender sends up to OTI_BURST blocks back to
 * back, flagging OTI_BF_MORE while more follow. The receiver keeps reading while
 * it sees OTI_BF_MORE and starts its own turn when the flag is clear.
 *
 * This driver claims the mass-storage interface itself, so usb-storage must
 * not be bound to it (see driver/README.md). It never sends the flash
 * commands F0 10 / F0 11 / F0 1B.
 */

#include <linux/crc32.h>		/* only to derive the MAC from the USB serial */
#include <linux/etherdevice.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/usb.h>

#include "oti2208_frame.h"

#define OTI_VID			0x0ea0
#define OTI_PID			0x2108

#define OTI_TXQ_MAX			1000
#define OTI_RXQ_MAX			4096	/* frames waiting for NAPI */
#define OTI_CMD_TIMEOUT_MS		5000
#define OTI_MAX_MTU		9000

/* D9 28 idle wait in 5 ms units; 2 measured best, 0 is ~40 % slower */
#define OTI_RX_WAIT		2
/* max blocks per turn before the peer may send */
#define OTI_BURST		32
/* max reads in a row while the peer says "more" */
#define OTI_RX_STREAK		64
/* write retries (refused or busy) before a block is dropped */
#define OTI_MAX_RETRIES		50

/* ---- Bulk-Only Transport ---- */

#define CBW_SIG			0x43425355u	/* "USBC" */
#define CSW_SIG			0x53425355u	/* "USBS" */

struct bot_cbw {
	__le32 sig;
	__le32 tag;
	__le32 len;
	u8 flags;
	u8 lun;
	u8 cblen;
	u8 cb[16];
} __packed;

struct bot_csw {
	__le32 sig;
	__le32 tag;
	__le32 residue;
	u8 status;
} __packed;

/* outcome of one SCSI command */
struct oti_res {
	int err;		/* <0: transport failure (errno) */
	u8 status;		/* CSW status: 0 ok, 1 failed (sense valid), 2 phase error */
	u8 key, asc, ascq;
	u32 xferred;		/* data-stage bytes */
};

enum dstat {
	D_OK,
	D_IDLE,		/* 09/83, 09/84: read found no data */
	D_BUSY,		/* 09/87, or check with no sense */
	D_NOREAD,	/* 09/85: no read posted on the peer for ~1.3 s */
	D_COLLIDE,	/* 09/86: the peer holds the slot */
	D_RESYNC,	/* 09/88, 09/89 */
	D_OFFLINE,	/* 09/80, 09/81 */
	D_ABORT,	/* 09/91/90, 09/91/91 */
	D_CHECK,	/* any other sense */
	D_ERROR,	/* transport failure */
};

struct oti {
	struct usb_device *udev;
	struct usb_interface *intf;
	struct net_device *net;
	unsigned int pipe_in, pipe_out;

	/* DMA-able buffers */
	struct bot_cbw *cbw;
	struct bot_csw *csw;
	u8 *small;		/* replies of identify / register reads / sense */
	u8 *txblk, *rxblk;

	u32 tag;
	u32 d8_seq, rseq;
	bool chip_a0;

	struct sk_buff_head txq;
	struct sk_buff_head rxq;	/* received frames, delivered by NAPI */
	struct napi_struct napi;
	struct task_struct *thread;
	bool dead;		/* the device is gone or wedged; the thread idles */

	/* diagnostics, printed on ifdown */
	u64 collisions, noread, idle_reads, data_reads, bad_blocks, dups;
};

static void oti_reset_recovery(struct oti *o)
{
	int ifnum = o->intf->cur_altsetting->desc.bInterfaceNumber;

	/* Bulk-Only Mass Storage Reset, then clear both halts */
	usb_control_msg(o->udev, usb_sndctrlpipe(o->udev, 0), 0xff,
			USB_TYPE_CLASS | USB_RECIP_INTERFACE, 0, ifnum,
			NULL, 0, OTI_CMD_TIMEOUT_MS);
	usb_clear_halt(o->udev, o->pipe_in);
	usb_clear_halt(o->udev, o->pipe_out);
}

static bool fatal_err(int err)
{
	return err == -ENODEV || err == -ESHUTDOWN || err == -ENOENT;
}

static void parse_sense(const u8 *sb, unsigned int n, struct oti_res *r)
{
	u8 rc;

	if (n < 3)
		return;
	rc = sb[0] & 0x7f;
	if (rc == 0x70 || rc == 0x71) {
		r->key = sb[2] & 0x0f;
		r->asc = n > 12 ? sb[12] : 0;
		r->ascq = n > 13 ? sb[13] : 0;
	} else if ((rc == 0x72 || rc == 0x73) && n >= 4) {
		r->key = sb[1] & 0x0f;
		r->asc = sb[2];
		r->ascq = sb[3];
	}
}

/*
 * One SCSI command over BOT: CBW, optional data stage, CSW, and REQUEST
 * SENSE when the command failed. Returns 0 when a CSW was received (check
 * r->status / sense), or a negative errno on transport failure (also in
 * r->err; a BOT reset recovery has then been done unless the device is gone).
 */
static int oti_bot(struct oti *o, const u8 *cdb, unsigned int cdblen, bool in,
		   void *buf, u32 len, unsigned int timeout_ms,
		   struct oti_res *r, bool autosense)
{
	unsigned int pipe = in ? o->pipe_in : o->pipe_out;
	int act = 0, err, i;
	u32 tag = ++o->tag;

	memset(r, 0, sizeof(*r));
	memset(o->cbw, 0, sizeof(*o->cbw));
	o->cbw->sig = cpu_to_le32(CBW_SIG);
	o->cbw->tag = cpu_to_le32(tag);
	o->cbw->len = cpu_to_le32(len);
	o->cbw->flags = in ? 0x80 : 0x00;
	o->cbw->cblen = cdblen;
	memcpy(o->cbw->cb, cdb, cdblen);

	err = usb_bulk_msg(o->udev, o->pipe_out, o->cbw, sizeof(*o->cbw), &act,
			   OTI_CMD_TIMEOUT_MS);
	if (err)
		goto fail;

	if (len) {
		err = usb_bulk_msg(o->udev, pipe, buf, len, &act, timeout_ms);
		if (err == -EPIPE) {
			/* the device ended the data stage early with a stall */
			usb_clear_halt(o->udev, pipe);
			err = 0;
		}
		if (err)
			goto fail;
		r->xferred = act;
		/* a device that skips the data stage sends the CSW right away */
		if (in && act == sizeof(*o->csw) &&
		    get_unaligned_le32(buf) == CSW_SIG &&
		    get_unaligned_le32((u8 *)buf + 4) == tag) {
			memcpy(o->csw, buf, sizeof(*o->csw));
			r->xferred = 0;
			goto have_csw;
		}
	}

	for (i = 0; i < 2; i++) {
		err = usb_bulk_msg(o->udev, o->pipe_in, o->csw, sizeof(*o->csw),
				   &act, OTI_CMD_TIMEOUT_MS);
		if (err == -EPIPE) {
			usb_clear_halt(o->udev, o->pipe_in);
			continue;
		}
		if (!err && act == 0)	/* stray zero-length packet */
			continue;
		break;
	}
	if (err)
		goto fail;
	if (act != sizeof(*o->csw) || le32_to_cpu(o->csw->sig) != CSW_SIG ||
	    le32_to_cpu(o->csw->tag) != tag) {
		err = -EPROTO;
		goto fail;
	}

have_csw:
	r->status = o->csw->status;
	if (r->status == 1 && autosense) {
		static const u8 rs[6] = { 0x03, 0, 0, 0, 18, 0 };
		struct oti_res sr;

		memset(o->small, 0, 18);
		if (oti_bot(o, rs, sizeof(rs), true, o->small, 18,
			    OTI_CMD_TIMEOUT_MS, &sr, false) == 0 && sr.status == 0)
			parse_sense(o->small, sr.xferred, r);
	} else if (r->status >= 2) {
		oti_reset_recovery(o);
		r->err = -EIO;
		return -EIO;
	}
	return 0;

fail:
	r->err = err;
	if (!fatal_err(err))
		oti_reset_recovery(o);
	return err;
}

static enum dstat classify(const struct oti_res *r)
{
	if (r->err)
		return D_ERROR;
	if (r->status == 0)
		return D_OK;
	if (r->key == 0 && r->asc == 0 && r->ascq == 0)
		return D_BUSY;
	if (r->key != 0x09)
		return D_CHECK;
	switch (r->asc) {
	case 0x80:
	case 0x81:
		return D_OFFLINE;
	case 0x83:
	case 0x84:
		return D_IDLE;
	case 0x85:
		return D_NOREAD;
	case 0x86:
		return D_COLLIDE;
	case 0x87:
		return D_BUSY;
	case 0x88:
	case 0x89:
		return D_RESYNC;
	case 0x91:
		return (r->ascq == 0x90 || r->ascq == 0x91) ? D_ABORT : D_CHECK;
	default:
		return D_CHECK;
	}
}

/* ---- vendor commands ---- */

static void vcdb(u8 cdb[16], u8 op, u8 sub)
{
	memset(cdb, 0, 16);
	cdb[0] = op;
	cdb[1] = sub;
	cdb[14] = 'O';
	cdb[15] = 'T';
}

static int oti_tur(struct oti *o, struct oti_res *r)
{
	static const u8 cdb[6];

	return oti_bot(o, cdb, sizeof(cdb), false, NULL, 0, OTI_CMD_TIMEOUT_MS, r, true);
}

static int oti_reg_set(struct oti *o, u8 reg, u16 val, struct oti_res *r)
{
	u8 cdb[16];

	vcdb(cdb, 0xd8, 0x01);
	cdb[2] = reg;
	cdb[3] = val >> 8;
	cdb[4] = val & 0xff;
	put_unaligned_be32(o->d8_seq, cdb + 5);
	o->d8_seq += 2;
	return oti_bot(o, cdb, 16, false, NULL, 0, OTI_CMD_TIMEOUT_MS, r, true);
}

static int oti_flush_rx(struct oti *o, struct oti_res *r)
{
	u8 cdb[16];

	vcdb(cdb, 0xd8, o->chip_a0 ? 0x00 : 0x01);
	cdb[2] = 0x0b;
	put_unaligned_be32(o->d8_seq, cdb + 5);
	o->d8_seq += 2;
	return oti_bot(o, cdb, 16, false, NULL, 0, OTI_CMD_TIMEOUT_MS, r, true);
}

/* F0 00 identify: 12-byte reply "Rd" 22 08 00 <ver> <6 ASCII date> */
static int oti_identify(struct oti *o)
{
	struct oti_res r;
	u8 cdb[16];
	u8 *b = o->small;
	int i;

	for (i = 0; i < 3; i++) {	/* the first TUR may report unit attention */
		if (oti_tur(o, &r) < 0 && fatal_err(r.err))
			return r.err;
		if (!r.err && r.status == 0)
			break;
	}

	vcdb(cdb, 0xf0, 0x00);
	memset(b, 0, 12);
	if (oti_bot(o, cdb, 16, true, b, 12, OTI_CMD_TIMEOUT_MS, &r, true) < 0)
		return r.err;
	if (r.status != 0 || r.xferred < 12)
		return -ENODEV;
	if (!(b[0] == 'R' && b[1] == 'd' && b[2] == 0x22 && b[3] == 0x08 && b[4] == 0) &&
	    !(b[0] == 0 && b[1] == 0 && b[2] == 0x21 && b[3] == 0x08 && b[4] == 0))
		return -ENODEV;
	o->chip_a0 = !memcmp(b + 6, "080613", 6);
	dev_info(&o->intf->dev, "OTi-2208 ver %u, firmware date %.6s\n", b[5], b + 6);
	return 0;
}

static int oti_write_block(struct oti *o, struct oti_res *r)
{
	u8 cdb[16];

	vcdb(cdb, 0xd9, 0x2a);
	cdb[2] = 0xff;
	return oti_bot(o, cdb, 16, false, o->txblk, OTI_BLOCK_SIZE, OTI_CMD_TIMEOUT_MS, r, true);
}

static int oti_read_block(struct oti *o, struct oti_res *r)
{
	u8 cdb[16];

	vcdb(cdb, 0xd9, 0x28);
	cdb[2] = OTI_RX_WAIT;
	put_unaligned_be32(o->rseq++, cdb + 5);
	return oti_bot(o, cdb, 16, true, o->rxblk, OTI_BLOCK_SIZE, OTI_CMD_TIMEOUT_MS, r, true);
}

static void oti_deliver(struct oti *o, const u8 *blk, int n)
{
	struct net_device *net = o->net;
	u32 off = 0;
	int i;

	for (i = 0; i < n; i++) {
		u16 fl = get_unaligned_le16(blk + OTI_PAYLOAD_OFF + off);
		const u8 *f = blk + OTI_PAYLOAD_OFF + off + OTI_FRAME_HDR;
		struct sk_buff *skb;

		off += OTI_FRAME_HDR + fl;
		if (fl < ETH_HLEN) {
			net->stats.rx_length_errors++;
			continue;
		}
		skb = netdev_alloc_skb_ip_align(net, fl);
		if (!skb) {
			net->stats.rx_dropped++;
			continue;
		}
		skb_put_data(skb, f, fl);
		skb->protocol = eth_type_trans(skb, net);
		if (skb_queue_len(&o->rxq) >= OTI_RXQ_MAX) {
			net->stats.rx_dropped++;
			dev_kfree_skb_any(skb);
			continue;
		}
		net->stats.rx_packets++;
		net->stats.rx_bytes += fl;
		skb_queue_tail(&o->rxq, skb);
	}
	/*
	 * Hand the frames to (threaded) NAPI instead of netif_rx(): the TCP
	 * receive work then runs in parallel with our next USB transfer, and GRO
	 * merges the ~43 segments of a block.
	 */
	if (!skb_queue_empty(&o->rxq))
		napi_schedule(&o->napi);
}

static int oti_poll(struct napi_struct *napi, int budget)
{
	struct oti *o = container_of(napi, struct oti, napi);
	struct sk_buff *skb;
	int done = 0;

	while (done < budget && (skb = skb_dequeue(&o->rxq))) {
		napi_gro_receive(napi, skb);
		done++;
	}
	/* frames queued after we found the queue empty are picked up here */
	if (done < budget && napi_complete_done(napi, done) &&
	    !skb_queue_empty(&o->rxq))
		napi_schedule(napi);
	return done;
}

/*
 * Fill txblk from the TX queue. Returns the number of frames packed; *more is
 * set when frames are still queued afterwards.
 */
static u16 oti_pack(struct oti *o, u32 *used_out, u32 *bytes_out, bool *more)
{
	struct sk_buff *skb;
	u32 used = 0, bytes = 0;
	u16 n = 0;

	*more = false;
	if (skb_queue_empty(&o->txq))
		return 0;
	memset(o->txblk, 0, OTI_BLOCK_SIZE);
	while (n < U16_MAX && (skb = skb_dequeue(&o->txq))) {
		if (used + OTI_FRAME_HDR + skb->len > OTI_PAYLOAD_MAX) {
			skb_queue_head(&o->txq, skb);
			break;
		}
		put_unaligned_le16(skb->len, o->txblk + OTI_PAYLOAD_OFF + used);
		skb_copy_bits(skb, 0, o->txblk + OTI_PAYLOAD_OFF + used + OTI_FRAME_HDR, skb->len);
		used += OTI_FRAME_HDR + skb->len;
		bytes += skb->len;
		n++;
		dev_consume_skb_any(skb);
	}
	if (netif_queue_stopped(o->net) && skb_queue_len(&o->txq) < OTI_TXQ_MAX / 2)
		netif_wake_queue(o->net);
	*used_out = used;
	*bytes_out = bytes;
	*more = !skb_queue_empty(&o->txq);
	return n;
}

/* ---- the data loop ---- */

static void oti_set_online(struct oti *o, bool on)
{
	if (on && !netif_carrier_ok(o->net)) {
		netif_carrier_on(o->net);
		netdev_info(o->net, "peer online\n");
	} else if (!on && netif_carrier_ok(o->net)) {
		netif_carrier_off(o->net);
		netdev_info(o->net, "peer offline\n");
	}
}

static int oti_thread(void *arg)
{
	struct oti *o = arg;
	struct net_device *net = o->net;
	struct oti_res r;
	u32 tx_seq = get_random_u32(), last_rx_seq = 0, tx_bytes = 0, tx_used = 0;
	u16 tx_nframes = 0;
	bool tx_pending = false, have_rx_seq = false, peer_more = false, sent_more = false;
	unsigned int tx_retries = 0, writes_since_read = 0, streak = 0, consec_err = 0;
	unsigned int tx_backoff = 0;

	while (!kthread_should_stop()) {
		bool need_read = true, drop = false, offline_wait = false;

		if (!tx_pending) {
			bool more;

			tx_nframes = oti_pack(o, &tx_used, &tx_bytes, &more);
			if (tx_nframes) {
				sent_more = more && writes_since_read + 1 < OTI_BURST;
				blk_finish(o->txblk, tx_seq, tx_nframes, tx_used,
					   sent_more ? OTI_BF_MORE : 0);
				tx_pending = true;
				tx_retries = 0;
			}
		}

		if (tx_pending && tx_backoff) {
			tx_backoff--;
		} else if (tx_pending && !(peer_more && streak < OTI_RX_STREAK)) {
			streak = 0;
			oti_write_block(o, &r);
			if (r.err && fatal_err(r.err))
				break;
			switch (classify(&r)) {
			case D_OK:
				net->stats.tx_packets += tx_nframes;
				net->stats.tx_bytes += tx_bytes;
				tx_seq++;
				tx_pending = false;
				consec_err = 0;
				writes_since_read++;
				if (sent_more)
					need_read = false;
				oti_set_online(o, true);
				break;
			case D_COLLIDE:
				/* the peer's block holds the slot: read it, then retry */
				o->collisions++;
				drop = ++tx_retries > OTI_MAX_RETRIES;
				break;
			case D_NOREAD:
				o->noread++;
				tx_backoff = 1 + get_random_u32_below(3);
				drop = ++tx_retries > OTI_MAX_RETRIES;
				break;
			case D_BUSY:
			case D_RESYNC:
			case D_IDLE:
			case D_CHECK:
				drop = ++tx_retries > OTI_MAX_RETRIES;
				break;
			case D_OFFLINE:
				oti_set_online(o, false);
				drop = true;
				break;
			case D_ABORT:
				drop = true;
				break;
			case D_ERROR:
				consec_err++;
				drop = ++tx_retries > OTI_MAX_RETRIES;
				break;
			}
			if (drop) {
				net->stats.tx_dropped += tx_nframes;
				tx_pending = false;
				tx_seq++;
			}
		}

		if (kthread_should_stop())
			break;
		if (!need_read)
			continue;
		writes_since_read = 0;

		oti_read_block(o, &r);
		if (r.err && fatal_err(r.err))
			break;
		switch (classify(&r)) {
		case D_OK: {
			int n = blk_check(o->rxblk, r.xferred);
			u32 seq;

			consec_err = 0;
			streak++;
			o->data_reads++;
			oti_set_online(o, true);
			if (n < 0) {
				peer_more = false;
				net->stats.rx_errors++;
				o->bad_blocks++;
				oti_flush_rx(o, &r);
				break;
			}
			seq = get_unaligned_le32(o->rxblk + 4);
			peer_more = o->rxblk[11] & OTI_BF_MORE;
			if (have_rx_seq && seq == last_rx_seq) {
				o->dups++;
				break;
			}
			oti_deliver(o, o->rxblk, n);
			last_rx_seq = seq;
			have_rx_seq = true;
			break;
		}
		case D_IDLE:
			streak = 0;
			peer_more = false;
			o->idle_reads++;
			oti_set_online(o, true);
			break;
		case D_OFFLINE:
			streak = 0;
			peer_more = false;
			oti_set_online(o, false);
			offline_wait = true;
			break;
		case D_ERROR:
			streak = 0;
			peer_more = false;
			consec_err++;
			if (r.err == -ETIMEDOUT)
				oti_flush_rx(o, &r);
			break;
		default:
			streak = 0;
			peer_more = false;
			break;
		}

		if (consec_err >= 20) {
			netdev_err(net, "too many transport errors, stopping\n");
			break;
		}
		if (offline_wait || !netif_carrier_ok(net)) {
			/* do not spin while the other side is absent */
			if (msleep_interruptible(200))
				break;
		}
	}

	/* fatal error or stop: idle until kthread_stop() */
	if (!kthread_should_stop()) {
		o->dead = true;
		oti_set_online(o, false);
		netdev_err(net, "data loop ended (device gone or not responding)\n");
		while (!kthread_should_stop()) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);
		}
		__set_current_state(TASK_RUNNING);
	}
	return 0;
}

/* ---- net_device ---- */

static int oti_open(struct net_device *net)
{
	struct oti *o = netdev_priv(net);
	struct oti_res r;
	int err;

	if (o->dead)
		return -ENODEV;
	/* EasySuite's connect: keep-alive 4000 ms, announce the host app */
	err = oti_reg_set(o, 0x04, 4000, &r);
	if (err && fatal_err(err))
		return err;
	err = oti_reg_set(o, 0x05, 0x007f, &r);
	if (err && fatal_err(err))
		return err;

	netif_carrier_off(net);
	napi_enable(&o->napi);
	o->thread = kthread_run(oti_thread, o, "%s-usb", net->name);
	if (IS_ERR(o->thread)) {
		err = PTR_ERR(o->thread);
		o->thread = NULL;
		napi_disable(&o->napi);
		return err;
	}
	netif_start_queue(net);
	return 0;
}

static int oti_stop(struct net_device *net)
{
	struct oti *o = netdev_priv(net);
	struct oti_res r;

	netif_stop_queue(net);
	if (o->thread) {
		kthread_stop(o->thread);
		o->thread = NULL;
	}
	napi_disable(&o->napi);
	skb_queue_purge(&o->rxq);
	skb_queue_purge(&o->txq);
	netif_carrier_off(net);
	if (!o->dead)
		oti_reg_set(o, 0x04, 1000, &r);	/* EasySuite does this on close */
	netdev_info(net, "collisions %llu, no-reader %llu, idle reads %llu, data reads %llu, bad blocks %llu, dups %llu\n",
		    o->collisions, o->noread, o->idle_reads, o->data_reads,
		    o->bad_blocks, o->dups);
	return 0;
}

static netdev_tx_t oti_start_xmit(struct sk_buff *skb, struct net_device *net)
{
	struct oti *o = netdev_priv(net);

	if (!skb->len || skb->len > OTI_FRAME_MAX) {
		net->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	/*
	 * Like tun: we may hold the skb for a while (until our turn on the
	 * half-duplex channel), so release the socket's accounting now.
	 * Otherwise TCP Small Queues throttles the sender to a fraction of the
	 * link (measured: 31 Mbit/s vs 160 Mbit/s for the TAP bridge). The
	 * queue below has its own limit, which stops the netdev queue.
	 */
	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC))) {
		net->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	skb_orphan(skb);
	skb_queue_tail(&o->txq, skb);
	if (skb_queue_len(&o->txq) >= OTI_TXQ_MAX)
		netif_stop_queue(net);
	return NETDEV_TX_OK;
}

static const struct net_device_ops oti_netdev_ops = {
	.ndo_open		= oti_open,
	.ndo_stop		= oti_stop,
	.ndo_start_xmit		= oti_start_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
};

/* ---- USB glue ---- */

static void oti_free(struct oti *o)
{
	kfree(o->cbw);
	kfree(o->csw);
	kfree(o->small);
	kfree(o->txblk);
	kfree(o->rxblk);
}

static int oti_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *in, *out;
	struct net_device *net;
	struct oti *o;
	u8 mac[ETH_ALEN];
	int err;

	err = usb_find_common_endpoints(intf->cur_altsetting, &in, &out, NULL, NULL);
	if (err)
		return -ENODEV;

	net = alloc_etherdev(sizeof(*o));
	if (!net)
		return -ENOMEM;
	o = netdev_priv(net);
	o->net = net;
	o->udev = udev;
	o->intf = intf;
	o->pipe_in = usb_rcvbulkpipe(udev, usb_endpoint_num(in));
	o->pipe_out = usb_sndbulkpipe(udev, usb_endpoint_num(out));
	skb_queue_head_init(&o->txq);
	skb_queue_head_init(&o->rxq);

	o->cbw = kmalloc(sizeof(*o->cbw), GFP_KERNEL);
	o->csw = kmalloc(sizeof(*o->csw) + 3, GFP_KERNEL);
	o->small = kmalloc(64, GFP_KERNEL);
	o->txblk = kmalloc(OTI_BLOCK_SIZE, GFP_KERNEL);
	o->rxblk = kmalloc(OTI_BLOCK_SIZE, GFP_KERNEL);
	if (!o->cbw || !o->csw || !o->small || !o->txblk || !o->rxblk) {
		err = -ENOMEM;
		goto fail;
	}

	/* the same USB ID may be other OTi hardware: require the 2208 reply */
	err = oti_identify(o);
	if (err) {
		dev_info(&intf->dev, "not an OTi-2208 bridge (identify: %d)\n", err);
		err = -ENODEV;
		goto fail;
	}

	/* a stable MAC from the USB serial number, which differs per cable end */
	if (udev->serial) {
		u32 c = crc32_le(~0u, udev->serial, strlen(udev->serial));

		mac[0] = 0x02;	/* locally administered */
		mac[1] = 0x22;
		mac[2] = c >> 24;
		mac[3] = c >> 16;
		mac[4] = c >> 8;
		mac[5] = c;
		eth_hw_addr_set(net, mac);
	} else {
		eth_hw_addr_random(net);
	}

	SET_NETDEV_DEV(net, &intf->dev);
	strscpy(net->name, "ezlink%d", sizeof(net->name));
	net->netdev_ops = &oti_netdev_ops;
	net->min_mtu = ETH_MIN_MTU;
	net->max_mtu = OTI_MAX_MTU;
	net->tx_queue_len = 100;	/* we queue up to OTI_TXQ_MAX ourselves */
	netif_carrier_off(net);
	/* threaded NAPI (set before adding the NAPI, like atl1c), see oti_deliver() */
	netif_threaded_enable(net);
	netif_napi_add(net, &o->napi, oti_poll);

	usb_set_intfdata(intf, o);
	err = register_netdev(net);
	if (err) {
		usb_set_intfdata(intf, NULL);
		goto fail;
	}
	netdev_info(net, "OTi-2208 USB bridge, %pM (serial %s)\n", net->dev_addr,
		    udev->serial ?: "?");
	return 0;

fail:
	oti_free(o);
	free_netdev(net);
	return err;
}

static void oti_disconnect(struct usb_interface *intf)
{
	struct oti *o = usb_get_intfdata(intf);

	if (!o)
		return;
	o->dead = true;
	unregister_netdev(o->net);	/* runs oti_stop() if up */
	usb_set_intfdata(intf, NULL);
	oti_free(o);
	free_netdev(o->net);
}

static const struct usb_device_id oti_ids[] = {
	{ USB_DEVICE_AND_INTERFACE_INFO(OTI_VID, OTI_PID, USB_CLASS_MASS_STORAGE, 0x06, 0x50) },
	{ }
};
MODULE_DEVICE_TABLE(usb, oti_ids);

static struct usb_driver oti_driver = {
	.name		= "oti2208_net",
	.id_table	= oti_ids,
	.probe		= oti_probe,
	.disconnect	= oti_disconnect,
	.disable_hub_initiated_lpm = 1,
};
module_usb_driver(oti_driver);

MODULE_DESCRIPTION("Ethernet over the OTi-2208 EasySuite USB host-to-host cable");
MODULE_LICENSE("GPL");
