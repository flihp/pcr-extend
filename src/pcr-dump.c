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

typedef struct dump_args {
    TPM_PCRINDEX pcr_index;
    bool pcr_set;
    bool verbose;
} dump_args_t;

const struct argp_option dump_opts[] = {
    {
        .name = "pcr",
        .key = 'p',
        .arg = "0-PCR_MAX",
        .flags = 0,
        .doc = "The PCR to dump.",
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

const struct argp dump_argp = {
    .options  = dump_opts,
    .parser   = parse_opts,
    .args_doc = NULL,
    .doc      = "Arguments for the PCR dump utility."
};

error_t
parse_opts (int key, char *arg, struct argp_state *state)
{
    dump_args_t *args = state->input;

    switch (key) {
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
dump_args_dump (dump_args_t *args)
{
    printf ("User provided options:\n");
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

/*  Read data from file object and dump into PCR till EOF or error.
 */
static int
dump_pcr (TPM_PCRINDEX index)
{
    TSS_RESULT result, out;
    TSS_HCONTEXT context;
    TSS_HTPM tpm;
    TSS_UNICODE *host = NULL; /* no remote connections */
    UINT32 pcr_before_len = 0;
    BYTE *pcr_before = NULL;

    result = Tspi_Context_Create (&context);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to create Tspi Context.\n");
        goto dump_out;
    }
    result = Tspi_Context_Connect (context, host);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to connect Tspi Context.\n");
        goto dump_out;
    }
    result = Tspi_Context_GetTpmObject (context, &tpm);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to get TPM object.\n");
        goto dump_out;
    }
    result = Tspi_TPM_PcrRead (tpm, index, &pcr_before_len, &pcr_before);
    if (result != TSS_SUCCESS) {
        fprintf (stderr, "Failed to read PCR %d: %s\n",
                 index, Trspi_Error_String (result));
        goto dump_out;
    }
    dump_buf (stdout, pcr_before, pcr_before_len);
dump_out:
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
    dump_args_t dump_args = { 0 };
    int ret = 0;

    if (ret = argp_parse (&dump_argp, argc, argv, 0, NULL, &dump_args)) {
        perror ("argp_parse: \n");
        goto main_out;
    }
    if (dump_args.verbose)
        dump_args_dump (&dump_args);
    if (dump_args.pcr_set == false) {
        ret = 1;
        fprintf (stderr, "No PCR provided.\n");
        goto main_out;
    }
    if (ret = dump_pcr (dump_args.pcr_index) != 0)
        goto main_out;
main_out:
    if (ret)
        exit (EXIT_FAILURE);
    exit (EXIT_SUCCESS);
}

