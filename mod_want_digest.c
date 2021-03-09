/* This code is licensed under the Apache License, Version 2.0
 * You may obtain a copy of the license at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * The function 'atoq' is taken from Apache httpd's mod_negotiation without modification.
 * The function 'get_entry' is a modified version from mod_negotiation.
 * The instance digests are calculated using the functions implemented in the Apache runtime (MD5, SHA) and zlib (ADLER32).
 * For an indication of additional information regarding copyright ownership, you are referred to the NOTICE file in Apache Software Foundation's httpd project.
*/

/* Include the required headers from httpd */
#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"

#include "apr_lib.h"
#include "apr_env.h"
#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_base64.h"
#include <apr_file_info.h>
#include <apr_file_io.h>

#include "util_filter.h"

#include "zlib.h"
#include "libgen.h"

module AP_MODULE_DECLARE_DATA want_digest_filter_module;
/* Define prototypes of our functions in this module */
//static void register_hooks(apr_pool_t *pool);
//static int want_digest_handler(request_rec *r);
//
//define filter names
static const char filter_name_put[] = "WANT_DIGEST_PUT";
static ap_filter_rec_t *filter_handle_put;

// struct for mapping the wanted digest algorithm and corresponding quality value from
// the 'Want-Digest' header token.
typedef struct digest_algorithm {
    float quality;
    char *name;
} digest_algorithm;

typedef struct st_md5 {
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char hex_digest[2*APR_MD5_DIGESTSIZE+1];
    apr_md5_ctx_t md5;
} st_md5;

typedef struct st_sha {
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    char hex_digest[2*APR_SHA1_DIGESTSIZE+1];
    apr_sha1_ctx_t sha1;
} st_sha;

// per-dir config with root path to hash storage dir
typedef struct wd_dir_config {
    char *digest_root_dir;
    char *error;
} wd_dir_config;

// struct for saving the filter context.
typedef struct want_digest_ctx {
    int lock;
    st_md5 *md5_ctx;
    st_sha *sha_ctx;
    size_t adler;
    const char *filename;
    char *digest_root_dir;
    apr_off_t remaining;
    int seen_eos;
    const char *filename_base;
    const char *filename_dir;
    const char *digest_save_path;
    const char *lock_filename;
} want_digest_ctx;

// the calculate_* functions have side effects (adding digests to headers_out), so we need to separate functionalities.
//
// calculates the md5 digest of a file and adds it to headers_out
void calculate_md5(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char hex_digest[2*APR_MD5_DIGESTSIZE+1];
    char b64_digest[apr_base64_encode_len(sizeof(hex_digest))];
    char final_digest[sizeof(b64_digest)+5];
    int len;
    apr_md5_ctx_t md5;
    apr_md5_init(&md5);

    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        apr_md5_update(&md5, buffer, readBytes);
    }
    apr_md5_final(digest, &md5);
    // rewrite binary form of digests into readable string output
    for (int i = 0; i<sizeof(digest); i++)
    {
       snprintf(&(hex_digest[i*2]), sizeof(hex_digest)-(i*2), "%02x", digest[i]); 
    }
    //hex_digest[sizeof(hex_digest)-1] = '\0';
    
    len = apr_base64_encode(b64_digest, hex_digest, sizeof(hex_digest));

    snprintf(&final_digest[0], sizeof(final_digest), "MD5=%s", b64_digest);
    apr_table_add(r->headers_out, "Digest", final_digest); 
}

// calculates the sha digest of a file and adds it to headers_out
void calculate_sha(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    char hex_digest[2*APR_SHA1_DIGESTSIZE+1];
    char b64_digest[apr_base64_encode_len(sizeof(hex_digest))];
    char final_digest[sizeof(b64_digest)+5];
    int len;
    apr_sha1_ctx_t sha1;
    apr_sha1_init(&sha1);

    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        apr_sha1_update(&sha1, buffer, readBytes);
    }
    apr_sha1_final(digest, &sha1);

    // rewrite binary form of digests into readable string output
    for (int i = 0; i<sizeof(digest); i++)
    {
       snprintf(&(hex_digest[i*2]), sizeof(hex_digest)-(i*2), "%02x", digest[i]); 
    }
    //hex_digest[sizeof(hex_digest)-1] = '\0';

    len = apr_base64_encode(b64_digest, hex_digest, sizeof(hex_digest));
    snprintf(&final_digest[0], sizeof(final_digest), "SHA=%s", b64_digest);
    apr_table_add(r->headers_out, "Digest", final_digest); 
}

// calculates the adler32 digest of a file and adds it to headers_out
void calculate_adler32(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    size_t adler = adler32_z(0L, Z_NULL, 0);
    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        adler = adler32_z(adler, buffer, readBytes);
    }

    char digest[17];
    sprintf(&digest[0], "ADLER32=%08lx", adler);
    apr_table_add(r->headers_out, "Digest", digest); 
}

// parses q-values from a string
// taken from httpd/modules/mappers/mod_negotiation.c
static float atoq(const char *string)
{
    if (!string || !*string) {
        return  1.0f;
    }

    while (apr_isspace(*string)) {
        ++string;
    }

    /* be tolerant and accept qvalues without leading zero
     * (also for backwards compat, where atof() was in use)
     */
    if (*string != '.' && *string++ != '0') {
        return 1.0f;
    }

    if (*string == '.') {
        /* better only one division later, than dealing with fscking
         * IEEE format 0.1 factors ...
         */
        int i = 0;

        if (*++string >= '0' && *string <= '9') {
            i += (*string - '0') * 100;

            if (*++string >= '0' && *string <= '9') {
                i += (*string - '0') * 10;

                if (*++string > '0' && *string <= '9') {
                    i += (*string - '0');
                }
            }
        }

        return (float)i / 1000.0f;
    }

    return 0.0f;
}

// adapted from httpd/modules/mappers/mod_negotiation.c
static const char *get_entry(apr_pool_t *p, digest_algorithm *result,
                             const char *accept_line)
{
    result->quality = 1.0f;

    /*
     * Note that this handles what I gather is the "old format",
     *
     *    Accept: text/html text/plain moo/zot
     *
     * without any compatibility kludges --- if the token after the
     * MIME type begins with a semicolon, we know we're looking at parms,
     * otherwise, we know we aren't.  (So why all the pissing and moaning
     * in the CERN server code?  I must be missing something).
     */

    result->name = ap_get_token(p, &accept_line, 0);
    ap_str_tolower(result->name);     /* You want case insensitive,
                                       * you'll *get* case insensitive.
                                       */

    /* KLUDGE!!! Default HTML to level 2.0 unless the browser
     * *explicitly* says something else.
     */

    while (*accept_line == ';') {
        /* Parameters ... */

        char *parm;
        char *cp;
        char *end;

        ++accept_line;
        parm = ap_get_token(p, &accept_line, 1);

        /* Look for 'var = value' --- and make sure the var is in lcase. */

        for (cp = parm; (*cp && !apr_isspace(*cp) && *cp != '='); ++cp) {
            *cp = apr_tolower(*cp);
        }

        if (!*cp) {
            continue;           /* No '='; just ignore it. */
        }

        *cp++ = '\0';           /* Delimit var */
        while (apr_isspace(*cp) || *cp == '=') {
            ++cp;
        }

        if (*cp == '"') {
            ++cp;
            for (end = cp;
                 (*end && *end != '\n' && *end != '\r' && *end != '\"');
                 end++);
        }
        else {
            for (end = cp; (*end && !apr_isspace(*end)); end++);
        }
        if (*end) {
            *end = '\0';        /* strip ending quote or return */
        }
        ap_str_tolower(cp);

        if (parm[0] == 'q'
            && (parm[1] == '\0' || (parm[1] == 's' && parm[2] == '\0'))) {
            result->quality = atoq(cp);
        }
    }

    if (*accept_line == ',') {
        ++accept_line;
    }

    return accept_line;
}

// the handler function that takes care of the request.
static int want_digest_get(request_rec *r)
{
    // variables
    int rc, file_exists, hash_exists, len;
    apr_finfo_t finfo;
    apr_file_t* file;
    char *filename, *hash_filename;
    char buffer[512];
    apr_size_t readBytes = 256;
    int n, num_digests;
    const char* digest_string;

    // check incoming headers
    if (NULL == (digest_string = apr_table_get(r->headers_in, "Want-Digest"))) return DECLINED;

    // Figure out which file is being requested
    filename = apr_pstrdup(r->pool, r->filename);

    // Check if the file a digest is requested for exists and that it isn't a directory, otherwise don't serve the request
    rc = apr_stat(&finfo, filename, APR_FINFO_NORM, r->pool);
    if (rc == APR_SUCCESS) 
    {
        file_exists = ( !(finfo.filetype & APR_NOFILE) && !(finfo.filetype & APR_DIR));
        if (!file_exists) return HTTP_NOT_FOUND; // Return a 404 if not found.
    }
    else if (rc == 2) return HTTP_NOT_FOUND; // If apr_stat returns 2, the file does not exist. same return value as the system function stat.
    else return HTTP_FORBIDDEN; // If apr_stat failed, we're probably not allowed to check this file.

    // get DigestRootDir from cfg
    wd_dir_config *cfg = ap_get_module_config(r->per_dir_config,
                                        &want_digest_filter_module);
    char *digest_root_dir = cfg->digest_root_dir;

    // sort wanted digests into array for processing and check if chached hashes exist.
    apr_array_header_t *wanted_digests;
    wanted_digests = apr_array_make(r->pool, 40, sizeof(digest_algorithm));
    while(*digest_string){
        digest_algorithm *new = (digest_algorithm *) apr_array_push(wanted_digests);
        digest_string = get_entry(r->pool, new, digest_string);
    }

    // Check for each algorithm if digest has been cached, if so, return from cache, otherwise calculate it
    
    digest_algorithm *digests_to_calc = (digest_algorithm *) wanted_digests->elts;
    for(int i=0; i<wanted_digests->nelts; i++)
    { 
    
    // Which digest type are we looking at here?
        if (!strcasecmp(digests_to_calc[i].name, "md5"))
        {
            hash_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".md5", NULL);
            hash_exists = apr_stat(&finfo, hash_filename, APR_FINFO_NORM, r->pool);
            if (hash_exists == 0)
            {
                rc = apr_file_open(&file, hash_filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    char hash_buf[finfo.size];
                    char b64_digest[apr_base64_encode_len(sizeof(hash_buf))];
                    char final_digest[sizeof(b64_digest)+4];

                    rc = apr_file_read(file, &hash_buf, &finfo.size);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                                 "Read MD5 digest %s from file of size %li.", hash_buf, finfo.size);
                    len = apr_base64_encode(b64_digest, hash_buf, sizeof(hash_buf));
                    snprintf(&final_digest[0], len, "MD5=%s", b64_digest);


                    apr_table_add(r->headers_out, "Digest", final_digest); 
                }
                else return 500;
                apr_file_close(file);
            }
            else
            {
                rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    calculate_md5(r, file, buffer, readBytes);
                }
                else return 500;
                apr_file_close(file);
            }
        }
        else if (!strcasecmp(digests_to_calc[i].name, "sha")) 
        {
            hash_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".sha", NULL);
            hash_exists = apr_stat(&finfo, hash_filename, APR_FINFO_NORM, r->pool);
            if (hash_exists == 0)
            {
                rc = apr_file_open(&file, hash_filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    char hash_buf[finfo.size];
                    char b64_digest[apr_base64_encode_len(sizeof(hash_buf))];
                    char final_digest[sizeof(b64_digest)+4];

                    rc = apr_file_read(file, &hash_buf, &finfo.size);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                                 "Read SHA digest %s from file of size %li.", hash_buf, finfo.size);
                    len = apr_base64_encode(b64_digest, hash_buf, sizeof(hash_buf));
                    snprintf(&final_digest[0], len, "SHA=%s", b64_digest);

                    apr_table_add(r->headers_out, "Digest", final_digest); 
                }
                else return 500;
                apr_file_close(file);
            }
            else
            {
                rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    calculate_sha(r, file, buffer, readBytes);
                }
                else return 500;
                apr_file_close(file);
            }
        }
        else if (!strcasecmp(digests_to_calc[i].name, "adler32"))
        {
            hash_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".adler32", NULL);
            hash_exists = apr_stat(&finfo, hash_filename, APR_FINFO_NORM, r->pool);
            if (hash_exists == 0)
            {
                rc = apr_file_open(&file, hash_filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    char final_digest[finfo.size+8];
                    char hash_buf[finfo.size];
                    rc = apr_file_read(file, &hash_buf, &finfo.size);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                                 "Read ADLER32 digest %s from file %li.", hash_buf, finfo.size);
                    snprintf(&final_digest[0], sizeof(final_digest), "ADLER32=%s", hash_buf);

                    apr_table_add(r->headers_out, "Digest", final_digest); 
                }
                else return 500;
                apr_file_close(file);
            }
            else
            {
                rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT, r->pool);
                if (rc == APR_SUCCESS)
                {
                    calculate_adler32(r, file, buffer, readBytes);
                }
                else return 500;
                apr_file_close(file);
            }
        }
        else
        {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                     "digestType: %s unknown, no header returned.", digest_string);
        }
    }

    // Let Apache know that we responded to this request.
    // Somehow, if we say OK or DONE, the request processing chain ends here and nothing else is done...
    // Implementation as a dynamic filter seems to be more fitting for this kind of task...
    return DECLINED;
}

// when the input filter function is added to the filter chain on PUT it calculates the hashes of the file
// on-the-fly and stores them as files in a replicated directory tree outside of the directory served by WebDAV. 
static apr_status_t want_digest_put_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                             ap_input_mode_t mode,
                                             apr_read_type_e block,
                                             apr_off_t readbytes)
{
    apr_bucket *bucket;
    apr_status_t rv;
    const char *data;
    char *filepath, *filename, *path, *new_path;
    apr_file_t *fhandle;
    apr_size_t len;
    apr_finfo_t finfo;
    // the context for this filter
    want_digest_ctx *ctx = f->ctx;
    // per-dir config
    wd_dir_config *cfg = ap_get_module_config(f->r->per_dir_config,
                                        &want_digest_filter_module);

    if (mode != AP_MODE_READBYTES) 
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                     "mode was not readbytes.");
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (!ctx)
    {
        // allocate context itself
        ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        // allocate hash ctx for md5 and sha and intialize all three
        ctx->md5_ctx = apr_pcalloc(f->r->pool, sizeof(*ctx->md5_ctx));
        ctx->sha_ctx = apr_pcalloc(f->r->pool, sizeof(*ctx->sha_ctx));
        apr_md5_init(&(ctx->md5_ctx->md5));
        apr_sha1_init(&(ctx->sha_ctx->sha1));
        ctx->adler = adler32_z(0L, Z_NULL, 0);
        // directory paths for ctx
        ctx->filename = f->r->filename;
        ctx->digest_root_dir = cfg->digest_root_dir;
        ctx->filename_dir = dirname(apr_pstrdup(f->r->pool, ctx->filename));
        ctx->filename_base = basename(apr_pstrdup(f->r->pool, ctx->filename));
        ctx->digest_save_path = apr_pstrcat(f->r->pool, ctx->digest_root_dir, ctx->filename_dir, NULL);
        rv = apr_dir_make_recursive(ctx->digest_save_path, APR_FPROT_OS_DEFAULT, f->r->pool);
        // status variables in ctx
        ctx->seen_eos = 0;
        ctx->remaining = 0;
        ctx->lock = 0;
        // check for content-length, without it, we cannot proceed.
        if (apr_table_get(f->r->headers_in, "Content-Length"))
        {
            ctx->remaining = atoi(apr_table_get(f->r->headers_in, "Content-Length"));
        }
        else
        {
            ap_remove_input_filter(f);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                         "No content-length given, stepping aside.");
            return APR_SUCCESS;
        }
        // finally: check for the lockfile, if any other application is dealing with digests at the moment,
        // do not interfere!
        ctx->lock_filename = apr_pstrcat(f->r->pool, ctx->digest_save_path, "/", ctx->filename_base, ".lock", NULL);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                     "ctx->lock_filename: %s.", ctx->lock_filename);
        rv = apr_stat(&finfo, ctx->lock_filename, APR_FINFO_NORM, f->r->pool);
        if (rv == APR_SUCCESS && ctx->lock == 0) 
        {
            ap_remove_input_filter(f);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                         "Digest lock file for %s in place, stepping aside.", ctx->filename);
            return APR_SUCCESS;
        }
        else
        {
        // create lock file
        rv = apr_file_open(&fhandle, ctx->lock_filename, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_FPROT_OS_DEFAULT, f->r->pool);
        if (rv != APR_SUCCESS){
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                         "Unable to open lock file %s.", ctx->lock_filename);
        }
        rv = apr_file_close(fhandle);
        ctx->lock = 1;
        }
    }

    rv = ap_get_brigade(f->next,bb,mode,block,readbytes);
    if (rv != APR_SUCCESS) return rv;

    // get the buckets one by one
    for (bucket = APR_BRIGADE_FIRST(bb);
         bucket != APR_BRIGADE_SENTINEL(bb);
         bucket = APR_BUCKET_NEXT(bucket))

    {

        if (APR_BUCKET_IS_EOS(bucket) || ctx->remaining == 0)
        {
            ctx->seen_eos = 1;
            break;
        }
        else if (APR_BUCKET_IS_METADATA(bucket))
        {
            continue;
        }
        else if (ctx->remaining < 0)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                         "ctx->remaining < 0");
            // delete lock file
            if (ctx-> lock == 1)
            {
                if (apr_file_remove(ctx->lock_filename, f->r->pool) != APR_SUCCESS) return 500;
            }
            ap_remove_input_filter(f);
            break;
        }
        else
        {
            rv = apr_bucket_read(bucket, &data, &len, block);
            if (rv != APR_SUCCESS)
            {
                //error
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                             "Could not read from bucket...");
                return rv;
            }
            //update all hashes here!
            apr_md5_update(&(ctx->md5_ctx->md5), data, len);
            apr_sha1_update(&(ctx->sha_ctx->sha1), data, len);
            ctx->adler = adler32_z(ctx->adler, data, len);
            ctx->remaining -= len;

        }
    }

    if (ctx->remaining == 0 || ctx->seen_eos == 1)
    {
        // finalize hashes and write output files
        // MD5
        apr_md5_final(ctx->md5_ctx->digest, &(ctx->md5_ctx->md5));
        // SHA
        apr_sha1_final(ctx->sha_ctx->digest, &(ctx->sha_ctx->sha1));
        //ADLER32 is already finished at this point.
        
        // rewrite binary form of digests into readable string output
        for (int i = 0; i<sizeof(ctx->md5_ctx->digest); i++)
        {
           snprintf(&(ctx->md5_ctx->hex_digest[i*2]), sizeof(ctx->md5_ctx->hex_digest)-(i*2), "%02x", ctx->md5_ctx->digest[i]); 
        }
        ctx->md5_ctx->hex_digest[sizeof(ctx->md5_ctx->hex_digest)-1] = '\0';

        for (int i = 0; i<sizeof(ctx->sha_ctx->digest); i++)
        {
           snprintf(&ctx->sha_ctx->hex_digest[i*2], sizeof(ctx->sha_ctx->hex_digest)-(i*2), "%02x", ctx->sha_ctx->digest[i]); 
        }
        ctx->sha_ctx->hex_digest[sizeof(ctx->sha_ctx->hex_digest)-1] = '\0';
        
        // now to save the hashes! 
        // create directory recursively to store the file's hashes
        rv = apr_dir_make_recursive(ctx->digest_save_path, APR_FPROT_OS_DEFAULT, f->r->pool);

        // prepare paths
        char *md5_filename = apr_pstrcat(f->r->pool, ctx->digest_save_path, "/", ctx->filename_base, ".md5", NULL);
        apr_size_t md5_len = sizeof(ctx->md5_ctx->hex_digest);
        char *sha_filename = apr_pstrcat(f->r->pool, ctx->digest_save_path, "/", ctx->filename_base, ".sha", NULL);
        apr_size_t sha_len = sizeof(ctx->sha_ctx->hex_digest);
        char *adler32_filename = apr_pstrcat(f->r->pool, ctx->digest_save_path, "/", ctx->filename_base, ".adler32", NULL);
        char adler32[sizeof(ctx->adler)+1];
        snprintf(adler32, sizeof(adler32), "%08lx", ctx->adler);
        apr_size_t adler32_len = sizeof(adler32);

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                     "Writing digests for %s.", ctx->filename);
        // create and write files
        rv = apr_file_open(&fhandle, md5_filename, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_FPROT_OS_DEFAULT, f->r->pool);
        rv = apr_file_write(fhandle, &ctx->md5_ctx->hex_digest, &md5_len);
        rv = apr_file_close(fhandle);
        
        rv = apr_file_open(&fhandle, sha_filename, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_FPROT_OS_DEFAULT, f->r->pool);
        rv = apr_file_write(fhandle, &ctx->sha_ctx->hex_digest, &sha_len);
        rv = apr_file_close(fhandle);

        rv = apr_file_open(&fhandle, adler32_filename, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_FPROT_OS_DEFAULT, f->r->pool);
        rv = apr_file_write(fhandle, &adler32, &adler32_len);
        rv = apr_file_close(fhandle);

        // delete lock file
        if (ctx-> lock == 1)
        {
            rv = apr_file_remove(ctx->lock_filename, f->r->pool);
        }
        
        // step aside
        ap_remove_input_filter(f);
    }
    return APR_SUCCESS;
}

// when it is added on a DELETE, it takes care of deleting the previously hashed files and the directory if it is empty.
static apr_status_t want_digest_delete(request_rec *r)
{
    int rv, empty;
    apr_finfo_t finfo;
    apr_dir_t *dir;
    char *filename, *digest_root_dir, *path, *delete_path;
    // get filename from request
    filename = apr_pstrdup(r->pool, r->filename);

    // get DigestRootDir from cfg
    wd_dir_config *cfg = ap_get_module_config(r->per_dir_config,
                                        &want_digest_filter_module);
    digest_root_dir = cfg->digest_root_dir;

    // build paths for eventually cached digests
    char *md5_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".md5", NULL);
    char *sha_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".sha", NULL);
    char *adler_filename = apr_pstrcat(r->pool, digest_root_dir, filename, ".adler32", NULL);

    // check if digests are cached for this file and delete them if they exist.
    rv = apr_stat(&finfo, md5_filename, APR_FINFO_NORM, r->pool);
    if (rv == APR_SUCCESS)
    {
        rv = apr_file_remove(md5_filename, r->pool);
    }
    rv = apr_stat(&finfo, sha_filename, APR_FINFO_NORM, r->pool);
    if (rv == APR_SUCCESS)
    {
        rv = apr_file_remove(sha_filename, r->pool);
    }
    rv = apr_stat(&finfo, adler_filename, APR_FINFO_NORM, r->pool);
    if (rv == APR_SUCCESS)
    {
        rv = apr_file_remove(adler_filename, r->pool);
    }

    path = dirname((char*)filename);
    delete_path = apr_pstrcat(r->pool, digest_root_dir, path, NULL);
    // check if directory is empty, if yes, delete it.
    // ideally, we would employ a function that checks the complete directory
    // tree up to digest_root_dir and deletes all empty directories on the way.
    // for now it just deletes the bottom-most directory.
    rv = apr_dir_open(&dir, delete_path, r->pool);
    int count = 0;
    empty=1;
    while ((rv = apr_dir_read(&finfo,APR_FINFO_NAME, dir)) == APR_SUCCESS)
    {
        count++;
        if (count > 2)
        {
            // directory contains more than just . and .., not empty!
            empty=0;
            break;
        }
    }
    rv = apr_dir_close(dir);

    if (empty=1)
    {
        // dir is empty, remove it.
        rv = apr_dir_remove(delete_path, r->pool);
    }

    return DECLINED;
}

static void insert_filter(request_rec *r){
    
    if (r->method_number == M_PUT ){
        ap_add_input_filter_handle(filter_handle_put, NULL, r, r->connection);
    }
}

static int want_digest_handler(request_rec *r)
{
    if (r->method_number == M_GET) return want_digest_get(r);
    else if (r->method_number == M_DELETE) return want_digest_delete(r);
    else return DECLINED;
}

static const char *wd_cmd_func(cmd_parms *cmd, void *config, const char *arg1)
{
    wd_dir_config *cfg = (wd_dir_config *)config;
    if (arg1 != NULL)
    {
        cfg->digest_root_dir = (char *)arg1;
    }
    else
    {
        return apr_psprintf(cmd->temp_pool,
                           "No root directory for digest caching configured!");
    }
    return NULL;
}

/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    // register input filter for PUT
    filter_handle_put = 
        ap_register_input_filter(filter_name_put, want_digest_put_filter, NULL, AP_FTYPE_RESOURCE);
    // hook handler for GET and DELETE, those are not handled by filters but by module functions
    ap_hook_handler(want_digest_handler, NULL, NULL, APR_HOOK_FIRST);
    // hook in function to add the filter to a PUT request
    ap_hook_insert_filter(insert_filter, NULL, NULL, APR_HOOK_LAST);
}

static void *create_per_dir_config(apr_pool_t *p, char *s)
{
    wd_dir_config *cfg = apr_pcalloc(p, sizeof(wd_dir_config));
    return cfg;
}

static const command_rec wd_commands[] = {
    AP_INIT_TAKE1("DigestRootDir", wd_cmd_func, NULL, ACCESS_CONF,
                  "Specify the root directory for storing cached digests."),
    {NULL}
};

/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA want_digest_filter_module =
{
    STANDARD20_MODULE_STUFF,
    create_per_dir_config, // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    wd_commands,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};
