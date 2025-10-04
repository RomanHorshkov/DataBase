/**
 * @file auth_interface.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "auth_interface.h"
#include "utils_interface.h" /* sanitize_email, uuid */

#include "db_interface.h"
#include "db_sodium.h"

static int auth_login_ops(DB_operation_t** operations, uint8_t* n_ops,
                          char* email, uint8_t elen)
{
    /* build the operation list to execute login :
       get user id
       get user pwd_hash
    */

    uint8_t N_OPERATIONS = 2;

    DB_operation_t* ops = calloc(N_OPERATIONS, sizeof(DB_operation_t));
    if(!ops)
    {
        fprintf(stderr, "[db_user] auth_login_ops calloc failure\n");
        return -ENOMEM;
    }

    /* --- op 0: email -> id --- */
    DB_operation_t* op = &ops[0];
    if(void_store_init(1, &op->key_store) != 0)
    {
        free(ops);
        return -ENOMEM;
    }
    void_store_add(op->key_store, (void*)email, (size_t)elen);
    ops_prepare_op(op, DB_OPERATION_GET, DB->db_user_mail2id, 0);

    /* --- op 1: id -> pwd --- */
    op = &ops[1];
    /* IMPORTANT: do NOT init key_store here. op_get will use op->prev->dst */
    ops_prepare_op(op, DB_OPERATION_GET, DB->db_user_id2pwd, 0);

    ops_link(ops, N_OPERATIONS);
    *n_ops      = N_OPERATIONS;
    *operations = ops;
    return 0;
}

int auth_login(char* email, char* pwd)
{
    int ret = -1;
    if(!email || !pwd)
    {
        fprintf(stdout, "[auth_login] invalid login parameters\n");
        ret = -EINVAL;
        goto fail;
    }

    uint8_t elen = 0;
    if(sanitize_email(email, DB_EMAIL_MAX_LEN, &elen) != 0)
    {
        ret = -EINVAL;
        goto fail;
    } 

    /* Prepare the operations data */
    DB_operation_t* ops   = NULL;
    uint8_t         n_ops = 0;

    /* create operations to add user */
    ret = auth_login_ops(&ops, &n_ops, email, elen);
    if(ret != 0)
    {
        goto fail;
    } 

    ret = ops_exec(ops, &n_ops);
    if(ret != 0)
    {
        ops_free(&ops, &n_ops);
        goto fail;
    }

    if(!ops[1].dst)
    {
        ops_free(&ops, &n_ops);
        ret = -EIO;
        goto fail;
    }
    
    /* sodium_verify_password returns 0 on OK */
    int ver = sodium_verify_password(pwd, ops[1].dst);
    ops_free(&ops, &n_ops);

    if(ver != 0)
    {
        fprintf(stdout, "[auth_login] invalid credentials %s\n", email);
        ret = -EPERM; /* or map/return proper error */
        goto fail;
    }

    fprintf(stdout, "[auth_login] LOG IN SUCC %s\n", email);
    return 0;

fail:
    fprintf(stdout, "[auth_login] LOG IN FAIL %s\n", email);
    return db_map_mdb_err(ret);
}

int auth_register_new(char* email, char* pwd)
{
    /* open DB */
    if(db_open("./med", 1ULL << 30) != 0)
    {
        puts("db_open failed");
        return -1;
    }

    /* init sodium */
    init_sodium();

    if(!email || !pwd) return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email, DB_EMAIL_MAX_LEN, &elen) != 0) return -EINVAL;

    /* generate uui7 user_id */
    uint8_t user_id[DB_UUID_SIZE];
    uuid_gen(user_id);

    /* password */
    char pwd_hash[crypto_pwhash_STRBYTES] = {'\0'};
    if(sodium_hash_password(pwd, pwd_hash) != 0) return -EIO;

    /* Register the new user on the DB */
    int rc = db_user_register_new(&elen, email, (uint8_t*)user_id, pwd_hash);

    if(rc != 0)
    {
        fprintf(stderr, "[auth_interface] db_user_register_new failed %d \n",
                rc);
        return rc;
    }

    sodium_memzero(pwd, strnlen(pwd, DB_PWD_MAX_HASH_SIZE));
    sodium_memzero(pwd_hash, strnlen(pwd_hash, DB_PWD_MAX_HASH_SIZE));

    return rc;
}
