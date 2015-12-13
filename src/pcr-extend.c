/*
 * Copyright (C) 2015 Philip Tricca <flihp@twobit.us>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <argp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

#define BUF_SIZE 1024

error_t
parse_opts (int key, char *arg, struct argp_state *state);

typedef struct extend_args {
    char *file;
    TPM_PCRINDEX pcr_index;
    bool pcr_set;
    bool verbose;
} extend_args_t;

const struct argp_option extend_opts[] = {
    {
        .name  = "file",
        .key   = 'f',
        .arg   = "file",
        .flags = 0,
        .doc   = "File containing data to extend into the PCR.",
        .group = 0,
    },
    {
        .name = "pcr",
        .key = 'p',
        .arg = "0-PCR_MAX",
        .flags = 0,
        .doc = "The PCR to extend.",
        .group = 0,
    },
    {
        .name = "verbose",
        .key = 'v',
        .arg = NULL,
        .flags = OPTION_ARG_OPTIONAL,
        .doc = "verbose",
        .group = 0,
    },
    { 0 }
};

const struct argp extend_argp = {
    .options  = extend_opts,
    .parser   = parse_opts,
    .args_doc = NULL,
    .doc      = "Arguments for the PCR extend utility."
};

error_t
parse_opts (int key, char *arg, struct argp_state *state)
{
    extend_args_t *args = state->input;

    switch (key) {
        case 'f':
            args->file = arg;
            break;
        case 'p':
            args->pcr_index = strtol (arg, NULL, 10);
            args->pcr_set = true;
            break;
        case 'v':
            args->verbose = true;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static void
extend_args_dump (extend_args_t *args)
{
    printf ("User provided options:\n");
    printf ("  file: %s\n", args->file);
    printf ("  pcr:  %d\n", args->pcr_index);
    printf ("  pcr_set: %s\n", args->pcr_set ? "true" : "false");
    printf ("  verbose: %s\n", args->verbose ? "true" : "false");
}

static void
dump_buf (FILE *file, char *buf, size_t length)
{
    int i;

    for (i = 0; i < length; ++i) {
        fprintf (file, "%02x ", (unsigned char)buf[i]);
    }
    fprintf (file, "\n");
}

static unsigned char*
sha1_file (FILE *file, unsigned int *hash_len)
{
    EVP_MD_CTX ctx = { 0 };
    unsigned char *buf = NULL, *hash = NULL;
    size_t num_read = 0;

    buf = malloc (BUF_SIZE);
    if (buf == NULL) {
        perror ("malloc:\n");
        goto sha1_fail;
    }
    if (EVP_DigestInit (&ctx, EVP_sha1 ()) == 0) {
        ERR_print_errors_fp (stderr);
        goto sha1_fail;
    }
    do {
        num_read = fread (buf, 1, BUF_SIZE, file);
        if (num_read <= 0)
            break;
        if (EVP_DigestUpdate (&ctx, buf, num_read) == 0) {
            ERR_print_errors_fp (stderr);
            goto sha1_fail;
        }
    } while (!feof (file) && !ferror (file));
    if (ferror (file)) {
        perror ("fread:\n");
        goto sha1_fail;
    }
    hash = calloc (1, EVP_MAX_MD_SIZE);
    if (hash == NULL) {
        perror ("calloc of hash buffer:\n");
        goto sha1_fail;
    }
    if (EVP_DigestFinal (&ctx, hash, hash_len) == 0) {
        ERR_print_errors_fp (stderr);
        goto sha1_fail;
    }
    if (buf)
        free (buf);
    return hash;
sha1_fail:
    if (buf)
        free (buf);
    if (hash)
        free (hash);
    return NULL;
}

/*  Read data from file object and extend into PCR till EOF or error.
 */
static int
extend_pcr (TPM_PCRINDEX index, char *hash, size_t hash_len)
{
    TSS_RESULT result, out;
    TSS_HCONTEXT context;
    TSS_HTPM tpm;
    TSS_UNICODE *host = NULL; /* no remote connections */
    UINT32 pcr_before_len = 0, pcr_after_len = 0;
    BYTE *pcr_before = NULL, *pcr_after = NULL;

    result = Tspi_Context_Create (&context);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to create Tspi Context.\n");
        goto extend_out;
    }
    result = Tspi_Context_Connect (context, host);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to connect Tspi Context.\n");
        goto extend_out;
    }
    result = Tspi_Context_GetTpmObject (context, &tpm);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to get TPM object.\n");
        goto extend_out;
    }
    result = Tspi_TPM_PcrRead (tpm, index, &pcr_before_len, &pcr_before);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to read PCR %d: %s\n",
                 index, Trspi_Error_String (result));
        goto extend_out;
    }
    fprintf (stdout, "Current value for PCR %d:\n  ", index);
    dump_buf (stdout, pcr_before, pcr_before_len);
    fprintf (stdout, "Extending PCR %d with data:\n  ", index);
    dump_buf (stdout, hash, hash_len);
    /* extend the PCR ... finally */
    result = Tspi_TPM_PcrExtend (tpm, index, hash_len, hash,
                                 NULL, &pcr_after_len, &pcr_after);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to extend PCR %d: %s\n",
                 index, Trspi_Error_String (result));
        goto extend_out;
    }
    fprintf (stdout, "New state for PCR %d:\n  ", index);
    dump_buf (stdout, pcr_after, pcr_after_len);
extend_out:
    out = result;
    /* shortcut to free all memory bound to the context */
    result = Tspi_Context_FreeMemory (context, NULL);
    if (result != TSS_SUCCESS)
        fprintf (stderr, "Failed to FreeMemory: %s\n", Trspi_Error_String (result));
    if (context) {
        result = Tspi_Context_Close (context);
        if (result != TSS_SUCCESS)
            fprintf (stderr, "Failed to close context: %s\n", Trspi_Error_String (result));
    }
    return out;
}

int
main (int argc, char *argv[])
{
    FILE *file = stdin;
    extend_args_t extend_args = { 0 };
    char *buf = NULL;
    unsigned int buf_len = 0;
    int ret = -1;

    if (argp_parse (&extend_argp, argc, argv, 0, NULL, &extend_args)) {
        perror ("argp_parse: \n");
        goto main_out;
    }
    if (extend_args.verbose)
        extend_args_dump (&extend_args);
    if (extend_args.pcr_set == false) {
        fprintf (stderr, "No PCR provided.\n");
        goto main_out;
    }
    if (extend_args.file) {
        file = fopen (extend_args.file, "r");
        if (file == NULL) {
            perror ("fopen:\n");
            goto main_out;
        }
    } else {
        file = stdin;
    }

    buf = sha1_file (file, &buf_len);
    if (buf == NULL)
        goto main_out;
    if (extend_pcr (extend_args.pcr_index, buf, buf_len) != 0)
        goto main_out;
    ret = 0;
main_out:
    if (file != stdin)
        fclose (file);
    if (buf)
        free (buf);
    if (ret == 0)
        exit (EXIT_SUCCESS);
    else
        exit (EXIT_FAILURE);
}

