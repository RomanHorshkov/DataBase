#include "db_internal.h"

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */
int db_put_reserve(MDB_txn *txn, const DB_operation_t *operations,
                   uint8_t n_operations, uint8_t *failed_op)
{
    if(!txn || !operations || n_operations <= 0) return -EINVAL;

    /* getting data loop */
    for(uint8_t i = 0; i < n_operations; ++i)
    {
        DB_operation_t *operation = &operations[i];

        /* Check operation params */
        if(!operation->val.ctx || !operation->val.size || !operation->val.write)
            return -EINVAL;

        MDB_val k = {.mv_size = operation->key.data_len,
                     .mv_data = (void *)operation->key.data_ptr};
        MDB_val v = {.mv_size = operation->val.size(operation->val.ctx),
                     .mv_data = NULL};

        int rc = mdb_put(txn, operation->dbi, &k, &v,
                         MDB_RESERVE | operation->flags);
        if(rc != MDB_SUCCESS)
        {
            printf("Nok mdb_put\n");
            if(failed_op) *failed_op = i;
            return rc;
        }

        /* remember where to write later */
        operation->dst     = v.mv_data;
        operation->dst_len = v.mv_size;
    }

    return MDB_SUCCESS;
}

int db_put_write_reserved(DB_operation_t *operations, uint8_t n_operations)
{
    if(!operations || n_operations <= 0) return -EINVAL;

    for(size_t i = 0; i < n_operations; ++i)
    {
        /* must be set by reserve pass */
        if(!operations[i].dst) return -EFAULT;

        operations[i].val.write(operations[i].dst, operations[i].val.ctx);
    }
    return MDB_SUCCESS;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */
