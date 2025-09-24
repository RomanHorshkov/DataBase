#include "utils_interface.h"

#include <errno.h>
#include <stddef.h>
#include <ctype.h> /* isspace */


static inline int is_local_allowed(unsigned char c)
{
    /* RFC 5322 (unquoted) pragmatic subset */
    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9'))
        return 1;
    switch(c)
    {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '/':
        case '=':
        case '?':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
        case '.':
            return 1;
        default:
            return 0;
    }
}

static inline int is_domain_allowed(unsigned char c)
{
    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9') || c == '-' || c == '.')
        return 1;
    return 0;
}

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

int sanitize_email(char *email, uint8_t email_max_len, uint8_t *out_len)
{
    if(!email || !out_len) return -ENOENT;

    /* Require a NUL within the buffer */
    size_t len = strnlen(email, email_max_len);
    if(len == 0 || len >= email_max_len) return -ENOENT;

    /* No leading/trailing spaces; no control chars/DEL/space anywhere */
    if(isspace((unsigned char)email[0]) ||
       isspace((unsigned char)email[len - 1]))
        return -ENOENT;
    for(size_t k = 0; k < len; ++k)
    {
        unsigned char c = (unsigned char)email[k];
        if(c <= 0x20 || c == 0x7F) return -ENOENT; /* forbid space & controls */
    }

    /* Exactly one '@' and split */
    char *at = memchr(email, '@', len);
    if(!at) return -ENOENT;
    if(memchr(at + 1, '@', (size_t)(email + len - (at + 1)))) return -ENOENT;

    size_t local_len  = (size_t)(at - email);
    size_t domain_len = len - local_len - 1;
    if(local_len == 0 || domain_len == 0) return -ENOENT;
    if(local_len > 64) return -ENOENT;

    /* Local-part: dot-atom, no leading/trailing dot, no ".." */
    {
        const unsigned char *p = (const unsigned char *)email;
        if(p[0] == '.' || p[local_len - 1] == '.') return -ENOENT;
        int prev_dot = 0;
        for(size_t k = 0; k < local_len; ++k)
        {
            unsigned char c = p[k];
            if(!is_local_allowed(c)) return -ENOENT;
            if(c == '.')
            {
                if(prev_dot) return -ENOENT;
                prev_dot = 1;
            }
            else
            {
                prev_dot = 0;
            }
        }
    }

    /* Domain: labels [A-Za-z0-9-], no leading/trailing '-', at least one dot,
       TLD length >= 2; lowercase domain in place */
    {
        unsigned char *p = (unsigned char *)(at + 1);
        if(p[0] == '.' || p[domain_len - 1] == '.') return -ENOENT;

        size_t label_len = 0;
        int    have_dot  = 0;
        for(size_t k = 0; k < domain_len; ++k)
        {
            unsigned char c = p[k];
            if(!is_domain_allowed(c)) return -ENOENT;

            /* lowercase in-place (domain only) */
            if(c >= 'A' && c <= 'Z')
            {
                c    = (unsigned char)(c - 'A' + 'a');
                p[k] = c;
            }

            if(c == '.')
            {
                have_dot = 1;
                if(label_len == 0) return -ENOENT;  /* empty label */
                if(p[k - 1] == '-') return -ENOENT; /* ends with '-' */
                if(label_len > 63) return -ENOENT;
                label_len = 0;
            }
            else
            {
                if(label_len == 0 && c == '-')
                    return -ENOENT; /* starts with '-' */
                label_len++;
            }
        }
        if(label_len == 0 || label_len > 63) return -ENOENT;
        if(!have_dot) return -ENOENT;
        if(label_len < 2) return -ENOENT; /* TLD >= 2 */
    }

    if(len > 255) return -ENOENT; /* fits uint8_t design */

    *out_len = (uint8_t)len;
    return 0;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */
/* None */
