/*
 * Card-agnostic Chip Authentication v1 (CA-ECDH-AES-CBC-CMAC-256, P-384).
 *
 * Derived from tools/session/npa-ca-v1-exact.inc, with the card-specific pins removed:
 *   - no fixed DG14 SHA-256 gate; instead the CA-v1 suite OID must be declared
 *     in the live DG14, and the card's static public key is parsed from it;
 *   - the possession proof is a CA-secure-messaging READ of EF.COM's first
 *     bytes returning 9000 (valid MAC under CA-derived keys), not a byte match.
 * It keeps the exact-sequence discipline (no PIN/PUK/TA/DG3/write/fallback) and
 * the original function name so the existing patch's call site is unchanged.
 */
#include "sm/sm-iso.h"
#include <eac/ca.h>
#include <eac/eac.h>
#include <string.h>

/* Portable substring search (no GNU memmem dependency). */
static int bytes_contain(const unsigned char *hay, size_t hl,
		const unsigned char *needle, size_t nl)
{
	size_t i;
	if (nl == 0 || hl < nl)
		return 0;
	for (i = 0; i + nl <= hl; i++)
		if (memcmp(hay + i, needle, nl) == 0)
			return 1;
	return 0;
}

BUF_MEM *KA_CTX_generate_key(const KA_CTX *ctx, BN_CTX *bn_ctx);
int KA_CTX_compute_key(KA_CTX *ctx, const BUF_MEM *in, BN_CTX *bn_ctx);
int KA_CTX_derive_keys(KA_CTX *ctx, const BUF_MEM *nonce, EVP_MD_CTX *md_ctx);

struct eac_sm_ctx_probe {
	EAC_CTX *ctx;
};

/* Locate the uncompressed P-384 point (0x04 || X || Y, 97 bytes) carried as the
 * SubjectPublicKey BIT STRING (03 62 00 04 ...) inside the live DG14. */
static const unsigned char *find_p384_point(const unsigned char *dg14, size_t dg14_len)
{
	size_t i;
	if (dg14_len < 101)
		return NULL;
	for (i = 0; i + 101 <= dg14_len; i++) {
		if (dg14[i] == 0x03 && dg14[i + 1] == 0x62 &&
				dg14[i + 2] == 0x00 && dg14[i + 3] == 0x04)
			return dg14 + i + 3;
	}
	return NULL;
}

static int perform_reference_chip_authentication_v1(sc_card_t *card,
		const unsigned char *dg14, size_t dg14_len)
{
	static const unsigned char protocol_oid[] = {
		0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x04
	};
	/* The suite OID as it appears in DG14 (06 0A <oid>). */
	static const unsigned char suite_in_dg14[] = {
		0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x04
	};
	unsigned char mse_data[15];
	unsigned char ga_data[101];
	unsigned char ga_response[256];
	unsigned char ef_com_response[4];
	const unsigned char *picc_point = NULL;
	BUF_MEM *picc_public_key_buf = NULL;
	BUF_MEM *pcd_ephemeral_public_key = NULL;
	struct iso_sm_ctx *iso_sm;
	struct eac_sm_ctx_probe *eac_sm;
	EAC_CTX *ctx;
	sc_apdu_t apdu;
	size_t offset = 0;
	int r = SC_ERROR_INTERNAL;

	if (!card || !dg14 || dg14_len < 101) {
		fprintf(stderr, "CA-v1 guard: live DG14 is absent or too short.\n");
		return SC_ERROR_INVALID_DATA;
	}
	/* Dynamic suite check: the card must declare CA-ECDH-AES-CBC-CMAC-256. */
	if (!bytes_contain(dg14, dg14_len, suite_in_dg14, sizeof suite_in_dg14)) {
		fprintf(stderr, "CA-v1 guard: DG14 does not declare the AES-256/P-384 CA-v1 suite.\n");
		return SC_ERROR_INVALID_DATA;
	}
	picc_point = find_p384_point(dg14, dg14_len);
	if (!picc_point) {
		fprintf(stderr, "CA-v1 guard: could not locate the P-384 public point in DG14.\n");
		return SC_ERROR_INVALID_DATA;
	}

	iso_sm = card->sm_ctx.info.cmd_data;
	if (!iso_sm || !iso_sm->priv_data) {
		fprintf(stderr, "CA-v1 guard: PACE secure-messaging context is absent.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	eac_sm = iso_sm->priv_data;
	ctx = eac_sm->ctx;
	if (!ctx || card->sm_ctx.sm_mode != SM_MODE_TRANSMIT) {
		fprintf(stderr, "CA-v1 guard: PACE secure messaging is not active.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (!EAC_CTX_init_ca(ctx, NID_id_CA_ECDH_AES_CBC_CMAC_256, 15)) {
		fprintf(stderr, "CA-v1 local setup: could not initialize P-384 CA context.\n");
		goto err;
	}
	ctx->ca_ctx->version = 1;
	ctx->ca_ctx->id = 0x30;
	pcd_ephemeral_public_key = KA_CTX_generate_key(ctx->ca_ctx->ka_ctx, ctx->bn_ctx);
	if (!pcd_ephemeral_public_key || pcd_ephemeral_public_key->length != 97
			|| (unsigned char) pcd_ephemeral_public_key->data[0] != 0x04) {
		fprintf(stderr, "CA-v1 local setup: terminal P-384 public key is invalid.\n");
		goto err;
	}
	bin_print(stdout, "CA-v1 terminal ephemeral public key",
			(unsigned char *) pcd_ephemeral_public_key->data,
			pcd_ephemeral_public_key->length);

	picc_public_key_buf = BUF_MEM_new();
	if (picc_public_key_buf && BUF_MEM_grow(picc_public_key_buf, 97) == 97)
		memcpy(picc_public_key_buf->data, picc_point, 97);
	else {
		BUF_MEM_clear_free(picc_public_key_buf);
		picc_public_key_buf = NULL;
	}
	if (!picc_public_key_buf
			|| !KA_CTX_compute_key(ctx->ca_ctx->ka_ctx, picc_public_key_buf, ctx->bn_ctx)
			|| !KA_CTX_derive_keys(ctx->ca_ctx->ka_ctx, NULL, ctx->md_ctx)) {
		fprintf(stderr, "CA-v1 local setup: ECDH or session-key derivation failed.\n");
		goto err;
	}

	mse_data[offset++] = 0x80;
	mse_data[offset++] = sizeof protocol_oid;
	memcpy(mse_data + offset, protocol_oid, sizeof protocol_oid);
	offset += sizeof protocol_oid;
	mse_data[offset++] = 0x84;
	mse_data[offset++] = 0x01;
	mse_data[offset++] = 0x30;
	if (offset != sizeof mse_data) {
		fprintf(stderr, "CA-v1 local setup: internal MSE length mismatch.\n");
		goto err;
	}

	sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xa4,
			mse_data, sizeof mse_data, NULL, 0);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0 || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen != 0) {
		fprintf(stderr, "CA-v1 MSE:Set AT failed (transport=%d, SW=%02X%02X, response=%zu).\n",
			r, apdu.sw1, apdu.sw2, apdu.resplen);
		r = r < 0 ? r : SC_ERROR_CARD_CMD_FAILED;
		goto err;
	}

	ga_data[0] = 0x7c;
	ga_data[1] = 0x63;
	ga_data[2] = 0x80;
	ga_data[3] = pcd_ephemeral_public_key->length;
	memcpy(ga_data + 4, pcd_ephemeral_public_key->data,
			pcd_ephemeral_public_key->length);
	sc_format_apdu_ex(&apdu, 0x00, 0x86, 0x00, 0x00,
			ga_data, sizeof ga_data, ga_response, sizeof ga_response);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0 || apdu.sw1 != 0x90 || apdu.sw2 != 0x00
			|| apdu.resplen != 2 || ga_response[0] != 0x7c || ga_response[1] != 0x00) {
		fprintf(stderr, "CA-v1 General Authenticate failed (transport=%d, SW=%02X%02X, response=%zu).\n",
			r, apdu.sw1, apdu.sw2, apdu.resplen);
		r = r < 0 ? r : SC_ERROR_CARD_CMD_FAILED;
		goto err;
	}

	if (!EAC_CTX_set_encryption_ctx(ctx, EAC_ID_CA)) {
		fprintf(stderr, "CA-v1 local setup: could not activate derived secure messaging.\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Possession proof: read EF.COM's first 4 bytes by SFI 30 under CA secure
	 * messaging. Success (9000 + valid MAC + EF.COM tag 0x60) proves the card
	 * derived the same CA session keys, i.e. it holds the private counterpart
	 * of the DG14 public key. The content itself is not personal data. */
	sc_format_apdu_ex(&apdu, 0x00, 0xb0, 0x9e, 0x00,
			NULL, 0, ef_com_response, sizeof ef_com_response);
	apdu.le = sizeof ef_com_response;
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0 || apdu.sw1 != 0x90 || apdu.sw2 != 0x00
			|| apdu.resplen != sizeof ef_com_response || ef_com_response[0] != 0x60) {
		fprintf(stderr, "CA-v1 EF.COM proof failed (transport=%d, SW=%02X%02X, response=%zu).\n",
			r, apdu.sw1, apdu.sw2, apdu.resplen);
		r = r < 0 ? r : SC_ERROR_INVALID_DATA;
		goto err;
	}

	bin_print(stdout, "CA-v1 EF.COM proof (first 4 bytes under CA SM)", ef_com_response, apdu.resplen);
	printf("Performed Chip Authentication v1 against the live DG14 key.\n");
	printf("Verified EF.COM under CA secure messaging: chip possession proven.\n");
	r = SC_SUCCESS;

err:
	OPENSSL_cleanse(mse_data, sizeof mse_data);
	OPENSSL_cleanse(ga_data, sizeof ga_data);
	OPENSSL_cleanse(ga_response, sizeof ga_response);
	OPENSSL_cleanse(ef_com_response, sizeof ef_com_response);
	BUF_MEM_clear_free(picc_public_key_buf);
	BUF_MEM_clear_free(pcd_ephemeral_public_key);
	return r;
}
