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

/* Define prototypes of our functions in this module */
//static void register_hooks(apr_pool_t *pool);
//static int want_digest_handler(request_rec *r);
//
//define filter names
static const char filter_name_put[] = "WANT_DIGEST_PUT";
static const char filter_name_delete[] = "WANT_DIGEST_DELETE";
static const char filter_name_get[] = "WANT_DIGEST_GET";
static ap_filter_rec_t *filter_handle_put;
static ap_filter_rec_t *filter_handle_delete;
static ap_filter_rec_t *filter_handle_get;

// struct for mapping the wanted digest algorithm and corresponding quality value from
// the 'Want-Digest' header token.
typedef struct digest_algorithm {
    float quality;
    char *name;
} digest_algorithm;

typedef struct st_md5 {
    unsigned char digest[APR_MD5_DIGESTSIZE];
    apr_md5_ctx_t md5;
} st_md5;

typedef struct st_sha {
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t sha1;
} st_sha;

// calculates the md5 digest of a file and adds it to headers_out
void calculate_md5(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char b64_digest[apr_base64_encode_len(sizeof(digest))];
    char final_digest[sizeof(b64_digest)+4];
    int len;
    apr_md5_ctx_t md5;
    apr_md5_init(&md5);

    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        apr_md5_update(&md5, buffer, readBytes);
    }
    apr_md5_final(digest, &md5);
    
    len = apr_base64_encode(b64_digest, digest, sizeof(digest));

    sprintf(&final_digest[0], "MD5=%s", b64_digest);
    apr_table_add(r->headers_out, "Digest", final_digest); 
}

// calculates the sha digest of a file and adds it to headers_out
void calculate_sha(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    char b64_digest[apr_base64_encode_len(sizeof(digest))];
    char final_digest[sizeof(b64_digest)+4];
    int len;
    apr_sha1_ctx_t sha1;
    apr_sha1_init(&sha1);

    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        apr_sha1_update(&sha1, buffer, readBytes);
    }
    apr_sha1_final(digest, &sha1);

    len = apr_base64_encode(b64_digest, digest, sizeof(digest));
    sprintf(&final_digest[0], "SHA=%s", b64_digest);
    apr_table_add(r->headers_out, "Digest", final_digest); 
}

// calculates the adler32 digest of a file and adds it to headers_out
void calculate_adler32(request_rec *r, apr_file_t *file, char *buffer, apr_size_t readBytes){
    size_t adler = adler32_z(0L, Z_NULL, 0);
    while ( apr_file_read(file, buffer, &readBytes) == APR_SUCCESS ) {
        adler = adler32_z(adler, buffer, readBytes);
    }

    char digest[17];
    sprintf(&digest[0], "ADLER32=%lx", adler);
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


static int want_digest_put(request_rec *r)
{
    char *filepath, *filename, *path, *new_path;
    char *hashpath = "/var/www/hashes";
    int len;
    apr_status_t status;

    // filename in the request
    filepath = apr_pstrdup(r->pool, r->filename);
    // extract basename
    filename = basename(filepath);
    path = dirname(filepath);

    // get the path prefix for storing the hashes
    //status = apr_env_get(&hashpath, "HASHPATH", r->pool);
    //if (status != APR_SUCCESS) {
    //    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
    //                 "error in getting hashpath from env.");
    //    return 500;
    //}

    //len = sizeof(hashpath);
    //if (hashpath[len-1] =! '/'){
    //    new_path = apr_pstrcat(r->pool, hashpath, '/', path, NULL);
    //}
    //else {
        new_path = apr_pstrcat(r->pool, hashpath, path, NULL);
    //}

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                 "hashpath: %s, new_path: %s", hashpath, new_path);

    // create directory recursively to store the file's hashes
    status = apr_dir_make_recursive(new_path, APR_FPROT_OS_DEFAULT, r->pool);
    if (status != APR_SUCCESS) {
        return 500;
    }

    // create hash files in new_path

    return DECLINED;
}

static int want_digest_delete(request_rec *r)
{
    return DECLINED;
}

// the handler function that takes care of the request.
static int want_digest_get(request_rec *r)
{
    // variables
    int rc, exists;
    apr_finfo_t finfo;
    apr_file_t* file;
    char *filename;
    char buffer[512];
    apr_size_t readBytes = 256;
    int n, num_digests;
    const char* digest_string;

    // check incoming headers
    if (apr_table_get(r->headers_in, "Want-Digest") != NULL){
        digest_string = apr_table_get(r->headers_in, "Want-Digest");
    }
    else {
        return (DECLINED);
    }

    apr_array_header_t *wanted_digests;
    wanted_digests = apr_array_make(r->pool, 40, sizeof(digest_algorithm));
    while(*digest_string){
        digest_algorithm *new = (digest_algorithm *) apr_array_push(wanted_digests);
        digest_string = get_entry(r->pool, new, digest_string);
    }

    // Figure out which file is being requested
    filename = apr_pstrdup(r->pool, r->filename);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                 "filename requested: %s", filename);

    
    // Figure out if the file we request a sum on exists and isn't a directory
    rc = apr_stat(&finfo, filename, APR_FINFO_NORM, r->pool);
    if (rc == APR_SUCCESS) {
        exists = ( !(finfo.filetype & APR_NOFILE) && !(finfo.filetype & APR_DIR));
        if (!exists) return HTTP_NOT_FOUND; // Return a 404 if not found.
        
    } else if (rc == 2) {
        return HTTP_NOT_FOUND; // If apr_stat returns 2, the file does not exist. same return value as the system function stat.

    } else {
        return HTTP_FORBIDDEN; // If apr_stat failed, we're probably not allowed to check this file.
    }
    
    digest_algorithm *digests_to_calc = (digest_algorithm *) wanted_digests->elts;
    for(int i=0; i<wanted_digests->nelts;i++){

        rc = apr_file_open(&file, filename, APR_READ, APR_OS_DEFAULT, r->pool);
        if (rc == APR_SUCCESS) {
        
        // Which digest type are we looking at here?
            if (!strcasecmp(digests_to_calc[i].name, "md5")) {
                calculate_md5(r, file, buffer, readBytes);

            } else if (!strcasecmp(digests_to_calc[i].name, "sha")) {
                calculate_sha(r, file, buffer, readBytes);

            } else if (!strcasecmp(digests_to_calc[i].name, "adler32")) {
                calculate_adler32(r, file, buffer, readBytes);

            } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, APLOGNO()
                         "digestType: %s unknown, no header returned.", digest_string);
            }
        }

        apr_file_close(file);
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
    const char *data, *filename;
    apr_size_t len;

    filename = f->r->filename;

    st_md5 *md5_data = apr_palloc(f->r->pool, sizeof(*md5_data));
    apr_md5_init(&(md5_data->md5));

    st_sha *sha_data = apr_palloc(f->r->pool, sizeof(*sha_data));
    apr_sha1_init(&(sha_data->sha1));

    size_t adler = adler32_z(0L, Z_NULL, 0);
    // get the buckets one by one
    for (bucket = APR_BRIGADE_FIRST(bb);
         bucket != APR_BRIGADE_SENTINEL(bb);
         bucket = APR_BUCKET_NEXT(bucket))
    {
        if (APR_BUCKET_IS_EOS(bucket))
        {
            break;
        }
        else if (APR_BUCKET_IS_METADATA(bucket))
        {
            continue;
        }
        else
        {
            rv = apr_bucket_read(bucket, &data, &len, APR_NONBLOCK_READ);
            if (rv != APR_SUCCESS)
            {
                //error
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->r->server, APLOGNO()
                             "Could not read from bucket...");
                return 500;
            }
            //update all hashes here!
            apr_md5_update(&(md5_data->md5), data, len);
            apr_sha1_update(&(sha_data->sha1), data, len);
            adler = adler32_z(adler, data, len);
        }
    }

    // finalize hashes and write output files
    // MD5
    apr_md5_final(md5_data->digest, &(md5_data->md5));
    apr_sha1_final(sha_data->digest, &(sha_data->sha1));
    //ADLER32 is already finished at this point.
   
    // now to save the hashes somwhere!
    return APR_SUCCESS;
}

// when it is added on a DELETE, it takes care of deleting the previously hashed files and the directory if it is empty.
static apr_status_t want_digest_delete_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                             ap_input_mode_t mode,
                                             apr_read_type_e block,
                                             apr_off_t readbytes)
{
   
    return APR_SUCCESS;
}

// the output filter checks if hashes are calculated and if they are, it just adds them to r->headers_out,
// otherwise it calculates and stores the hashes. can we get it to reuse the funcitonality of
// want_digest_put_filter?
static apr_status_t want_digest_get_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
   
    return APR_SUCCESS;
}

static void insert_filter(request_rec *r){
    
    if (r->method_number == M_PUT ){
        ap_add_input_filter_handle(filter_handle_put, NULL, r, r->connection);
    }
    if (r->method_number == M_DELETE) {
        ap_add_input_filter_handle(filter_handle_delete, NULL, r, r->connection);
    }
    if (r->method_number == M_GET) {
        ap_add_output_filter_handle(filter_handle_get, NULL, r, r->connection);
    }
}

/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    // register and add in/output filters
    filter_handle_put = 
        ap_register_input_filter(filter_name_put, want_digest_put_filter, NULL, AP_FTYPE_RESOURCE);
    filter_handle_delete = 
        ap_register_input_filter(filter_name_delete, want_digest_delete_filter, NULL, AP_FTYPE_RESOURCE);
    filter_handle_get = 
        ap_register_output_filter(filter_name_get, want_digest_get_filter, NULL, AP_FTYPE_RESOURCE);
    // hook in function to add the filters to the current request
    ap_hook_insert_filter(insert_filter, NULL, NULL, APR_HOOK_LAST);
}

/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   want_digest_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    NULL,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};
