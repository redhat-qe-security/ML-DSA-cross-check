#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#define SEED_LEN 32

#define EXIT_OK    0
#define EXIT_FAIL  1
#define EXIT_USAGE 2

enum {
    MODE_PKEY_SIGN,
    MODE_DIGESTSIGN
};


/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static size_t sig_size_for_alg(const char *alg)
{
    if (strcmp(alg, "ML-DSA-44") == 0) return 2420;
    if (strcmp(alg, "ML-DSA-65") == 0) return 3309;
    if (strcmp(alg, "ML-DSA-87") == 0) return 4627;
    return 0;
}

static int read_message(FILE *f, unsigned char **out_data, size_t *out_len)
{
    unsigned char len_bytes[4];
    if (fread(len_bytes, 1, 4, f) != 4) {
        if (feof(f))
            return 0;  /* EOF, no more messages */
        return -1;     /* read error */
    }

    uint32_t mlen = ((uint32_t)len_bytes[0] << 24) |
                    ((uint32_t)len_bytes[1] << 16) |
                    ((uint32_t)len_bytes[2] << 8)  |
                     (uint32_t)len_bytes[3];

    unsigned char *buf = malloc(mlen);
    if (!buf)
        return -1;

    if (fread(buf, 1, mlen, f) != mlen) {
        free(buf);
        return -1;
    }

    *out_data = buf;
    *out_len = mlen;
    return 1;  /* success */
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                    */
/* ------------------------------------------------------------------ */

static EVP_PKEY *keygen_from_seed(const char *alg, const unsigned char *seed)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto end;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                          (void *)seed, SEED_LEN),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
        goto end;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        pkey = NULL;

end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int key_via_fromdata(const char *alg, const unsigned char *seed,
                            EVP_PKEY **ppkey)
{
    int ret = 0;
    EVP_PKEY *tmp = keygen_from_seed(alg, seed);
    if (!tmp)
        return 0;

    size_t pub_len = 0, priv_len = 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                         NULL, 0, &pub_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                         NULL, 0, &priv_len) <= 0) {
        EVP_PKEY_free(tmp);
        return 0;
    }

    unsigned char *pub = malloc(pub_len);
    unsigned char *priv = malloc(priv_len);
    if (!pub || !priv) {
        free(pub);
        free(priv);
        EVP_PKEY_free(tmp);
        return 0;
    }

    EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                     pub, pub_len, &pub_len);
    EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                     priv, priv_len, &priv_len);
    EVP_PKEY_free(tmp);

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!dctx) {
        free(pub);
        free(priv);
        return 0;
    }

    OSSL_PARAM dparams[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          pub, pub_len),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          priv, priv_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata_init(dctx) > 0 &&
        EVP_PKEY_fromdata(dctx, ppkey, EVP_PKEY_KEYPAIR, dparams) > 0)
        ret = 1;

    EVP_PKEY_CTX_free(dctx);
    free(pub);
    free(priv);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --algorithm <name> --seeds <file> --messages <file>\n"
            "       --signatures <outfile> --mode <mode> [--reuse-ctx] [--reuse-key]\n\n"
            "Arguments:\n"
            "  --algorithm   ML-DSA-44, ML-DSA-65, or ML-DSA-87\n"
            "  --seeds       File with 32-byte key generation seeds\n"
            "  --messages    File with length-prefixed messages\n"
            "  --signatures  Output file for generated signatures\n"
            "  --mode        Signing API to use (see modes below)\n"
            "  --reuse-ctx   Reuse signing context across operations\n"
            "  --reuse-key   Reuse EVP_PKEY via EVP_PKEY_fromdata() across seeds\n"
            "\nModes:\n"
            "  evp_pkey_sign    Sign via EVP_PKEY_sign_message_init + EVP_PKEY_sign\n"
            "  evp_digestsign   Sign via EVP_DigestSignInit_ex + EVP_DigestSign\n"
            "\n"
            "The --reuse-ctx and --reuse-key flags are orthogonal and combine\n"
            "with any mode, giving 2 x 2 x 2 = 8 configurations. All should\n"
            "produce identical output for the same inputs.\n",
            prog);
}

int main(int argc, char **argv)
{
    const char *alg = NULL;
    const char *seed_path = NULL;
    const char *msg_path  = NULL;
    const char *sig_path  = NULL;
    const char *mode_str  = NULL;
    int reuse_ctx = 0;
    int reuse_key = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return EXIT_OK;
        }
        if (strcmp(argv[i], "--reuse-ctx") == 0) {
            reuse_ctx = 1;
            continue;
        }
        if (strcmp(argv[i], "--reuse-key") == 0) {
            reuse_key = 1;
            continue;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
        if (strcmp(argv[i], "--algorithm") == 0)
            alg = argv[++i];
        else if (strcmp(argv[i], "--seeds") == 0)
            seed_path = argv[++i];
        else if (strcmp(argv[i], "--messages") == 0)
            msg_path = argv[++i];
        else if (strcmp(argv[i], "--signatures") == 0)
            sig_path = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0)
            mode_str = argv[++i];
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_USAGE;
        }
    }

    if (!alg || !seed_path || !msg_path || !sig_path || !mode_str) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    int mode;
    if (strcmp(mode_str, "evp_pkey_sign") == 0)
        mode = MODE_PKEY_SIGN;
    else if (strcmp(mode_str, "evp_digestsign") == 0)
        mode = MODE_DIGESTSIGN;
    else {
        fprintf(stderr, "Unknown mode: %s\n", mode_str);
        return EXIT_USAGE;
    }

    size_t sig_sz = sig_size_for_alg(alg);
    if (sig_sz == 0) {
        fprintf(stderr, "Unsupported algorithm: %s\n", alg);
        return EXIT_USAGE;
    }

    EVP_SIGNATURE *probe = EVP_SIGNATURE_fetch(NULL, alg, NULL);
    if (!probe) {
        fprintf(stderr, "Algorithm %s not available in this OpenSSL build\n",
                alg);
        ERR_print_errors_fp(stderr);
        return EXIT_USAGE;
    }
    EVP_SIGNATURE_free(probe);

    /* ---- open input files ---- */

    FILE *seed_file = fopen(seed_path, "rb");
    if (!seed_file) {
        fprintf(stderr, "Cannot open %s: %s\n", seed_path, strerror(errno));
        return EXIT_USAGE;
    }

    FILE *msg_file = fopen(msg_path, "rb");
    if (!msg_file) {
        fprintf(stderr, "Cannot open %s: %s\n", msg_path, strerror(errno));
        fclose(seed_file);
        return EXIT_USAGE;
    }

    /* ---- open output file ---- */

    FILE *outf = fopen(sig_path, "wb");
    if (!outf) {
        fprintf(stderr, "Cannot open %s for writing: %s\n",
                sig_path, strerror(errno));
        return EXIT_USAGE;
    }

    fprintf(stderr, "ML-DSA cross-check: %s, mode=%s%s%s\n", alg, mode_str,
            reuse_ctx ? ", reuse-ctx" : "", reuse_key ? ", reuse-key" : "");
    fprintf(stderr, "  Signature size: %zu\n", sig_sz);

    /* ---- signing loop ---- */

    int ret = EXIT_OK;
    unsigned char *sig_buf = malloc(sig_sz);
    unsigned char seed[SEED_LEN];
    unsigned char *msg_data = NULL;
    size_t msg_len = 0;
    EVP_PKEY *pkey = NULL;
    int deterministic = 1;
    OSSL_PARAM sign_params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC,
                                 &deterministic),
        OSSL_PARAM_construct_end()
    };
    size_t total_sigs = 0;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_SIGNATURE *sa = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if (mode == MODE_PKEY_SIGN)
        sa = EVP_SIGNATURE_fetch(NULL, alg, NULL);

    if (mode == MODE_DIGESTSIGN && reuse_ctx)
        mdctx = EVP_MD_CTX_new();

    /* Read one seed and one message at a time */
    while (1) {
        /* Read seed */
        if (fread(seed, 1, SEED_LEN, seed_file) != SEED_LEN) {
            if (feof(seed_file))
                break;  /* No more seeds */
            fprintf(stderr, "Error reading seed: %s\n", strerror(errno));
            ret = EXIT_FAIL;
            goto end;
        }

        /* Read message */
        int msg_ret = read_message(msg_file, &msg_data, &msg_len);
        if (msg_ret == 0) {
            fprintf(stderr, "No more messages (but seeds remain)\n");
            break;
        }
        if (msg_ret < 0) {
            fprintf(stderr, "Error reading message\n");
            ret = EXIT_FAIL;
            goto end;
        }

        /* Generate key from seed */
        if (reuse_key) {
            if (!key_via_fromdata(alg, seed, &pkey)) {
                fprintf(stderr, "Key import via fromdata failed for seed %zu\n",
                        total_sigs);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }
        } else {
            EVP_PKEY_free(pkey);
            pkey = keygen_from_seed(alg, seed);
            if (!pkey) {
                fprintf(stderr, "Key generation failed for seed %zu\n",
                        total_sigs);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }
        }

        /* Sign the message */
        size_t slen = sig_sz;

        if (mode == MODE_PKEY_SIGN) {
            /* For EVP_PKEY_sign, we need a fresh context for each key */
            pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            if (!pctx) {
                fprintf(stderr, "EVP_PKEY_CTX_new failed for signature %zu\n",
                        total_sigs);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }

            if (EVP_PKEY_sign_message_init(pctx, sa, sign_params) <= 0 ||
                EVP_PKEY_sign(pctx, sig_buf, &slen, msg_data, msg_len) <= 0) {
                fprintf(stderr, "Signing failed for signature %zu\n", total_sigs);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }

            EVP_PKEY_CTX_free(pctx);
            pctx = NULL;
        } else {
            if (!reuse_ctx) {
                mdctx = EVP_MD_CTX_new();
                if (!mdctx) {
                    fprintf(stderr, "EVP_MD_CTX_new failed for signature %zu\n",
                            total_sigs);
                    ret = EXIT_FAIL;
                    free(msg_data);
                    goto end;
                }
            }

            if (reuse_ctx && !EVP_MD_CTX_reset(mdctx)) {
                fprintf(stderr, "EVP_MD_CTX_reset failed for signature %zu\n",
                        total_sigs);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }

            if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL,
                                       pkey, sign_params) <= 0 ||
                EVP_DigestSign(mdctx, sig_buf, &slen, msg_data, msg_len) <= 0) {
                fprintf(stderr, "Signing failed for signature %zu\n", total_sigs);
                ERR_print_errors_fp(stderr);
                ret = EXIT_FAIL;
                free(msg_data);
                goto end;
            }

            if (!reuse_ctx) {
                EVP_MD_CTX_free(mdctx);
                mdctx = NULL;
            }
        }

        /* Write signature */
        if (fwrite(sig_buf, 1, sig_sz, outf) != sig_sz) {
            fprintf(stderr, "Write error: %s\n", strerror(errno));
            ret = EXIT_FAIL;
            free(msg_data);
            goto end;
        }

        free(msg_data);
        msg_data = NULL;
        total_sigs++;
    }

    fprintf(stderr, "Wrote %zu signatures to %s\n", total_sigs, sig_path);

end:
    if (reuse_ctx) {
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_free(mdctx);
    }
    EVP_SIGNATURE_free(sa);
    EVP_PKEY_free(pkey);
    free(sig_buf);
    fclose(outf);
    fclose(seed_file);
    fclose(msg_file);

    return ret;
}
