
#include <stdio.h>
#include <string.h>
#include "acl.h"
#include "auth.h"

int main()
{
    DB db;
    if(auth_crypto_init() != 0)
    {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }
    if(db_open(&db, "./meta", 256ULL << 20) != 0)
    {
        fprintf(stderr, "db open failed\n");
        return 1;
    }

    uuid16_t uid;
    int      rc = auth_register(&db, "alice@example.com", 17, "hunter2", &uid);
    if(rc && rc != -EEXIST) fprintf(stderr, "register rc=%d\n", rc);

    uuid16_t got;
    rc = auth_login(&db, "alice@example.com", 17, "hunter2", &got);
    printf("login rc=%d\n", rc);

    uuid16_t data;
    uuid_gen(&data);
    uuid16_t shared_with;
    rc = auth_share_with_user(&db, &data, /*rtype=*/1, "bob@example.com", 15,
                              &shared_with);
    printf("share rc=%d\n", rc);

    kv_dump_all(&db, stdout);

    db_close(&db);
    return 0;
}
