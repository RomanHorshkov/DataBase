/**
 * @file db_pwd.c
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_intern.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

int db_pwd_add(uint8_t *userid, void *data, size_t data_size, MDB_txn *txn)
{
    int transaction_exists = 0;
    int ret                = -1;

retry:
    if(!txn)
    {
        ret = mdb_txn_begin(DB->env, NULL, 0, &txn);
        if(ret != MDB_SUCCESS) return db_map_mdb_err(ret);
    }
    else
    {
        transaction_exists = 1;
    }

    unsigned db_pwd_put_flags = MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND;

    /* id->pwd_blob; if exists stop */
    MDB_val k_id2pwd = {.mv_size = DB_ID_SIZE, .mv_data = (void *)userid};
    MDB_val v_id2pwd = {.mv_size = data_size, .mv_data = NULL};

    ret = mdb_put(txn, DB->db_user_pwd, &k_id2pwd, &v_id2pwd, db_pwd_put_flags);

    db_mdb_put_safe(txn, key, keysize, data, data_size, flags)

        if(ret == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        txn     = NULL;
        int grc = db_env_mapsize_expand();       /* grow */
        if(grc != 0) return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry;                              /* retry after mem expansion */
    }
    if(ret != MDB_SUCCESS)
    {
        goto fail;
    }

    return ret;

fail:
    mdb_txn_abort(txn);
    return db_map_mdb_err(ret);
}
