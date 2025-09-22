# Static Architecture — Auth + DB (v1)

This document captures the *static* structure of the project: modules, public APIs, dependencies, and where external libraries are used. Dynamic behavior (runtime flows) will come next.

---

## Overview

```mermaid
flowchart LR
  %% High-level layers and dependencies

    subgraph EXTLIBS[external libs]
        LMDB[lmdb]
        SOD[libsodium]
        OSS[OpenSSL]
    end

    subgraph utils
        UTI1[fsutil.h]
        UTI2[uui7.h]
    end

    subgraph crypto
        CRY[sha256.h]
    end

    subgraph auth
        AUTH[auth_interface.h]
    end

    subgraph db
        DB[db_interface.h]
    end

    auth -->|uses| db
    db -->|dep| crypto
    auth -->|dep| crypto
    auth -->|dep| utils
    db -->|dep| utils
    utils ---|dep| EXTLIBS
    crypto ---|dep| EXTLIBS
    
```

## Auth details

```mermaid
flowchart LR
    subgraph auth
        AUTHI[auth_interface.h]
        ASRV[auth_service.c]
        AUTHINT[auth_internal.h]
        APW[password.c]
        ASE[session.c]

        AUTHI --> ASRV
        AUTHI --> APW
        AUTHI --> ASE

        ASRV --> AUTHINT
        APW --> AUTHINT
        ASE --> AUTHINT
    end

    subgraph DB[db]
        DBI[db_interface.h]
    end

    subgraph CRY[crypto]
    end

    subgraph UTI[utils]
    end

    auth -->|uses| DB
    auth -->|dep| CRY
    auth -->|dep| UTI
```

## DB details

```mermaid
flowchart LR
    subgraph db
        DBI[db_interface.h]
        DEN[db_env.c]
        DUS[db_users.c]
        DDT[db_data.c]
        DAC[db_acl.c]
        DBI --> DEN
        DBI --> DUS
        DBI --> DDT
        DBI --> DAC
        DBINT[db_internal.h]
        DEN --> DBINT
        DUS --> DBINT
        DDT --> DBINT
        DAC --> DBINT

    end
    subgraph CRY[crypto]
    end

    subgraph UTI[utils]
    end

    db -->|dep| CRY
    db -->|dep| UTI

```

## Crypto details

```mermaid
flowchart TD
    subgraph crypto
        SHA_C[sha256.c]
    end

    subgraph EXTLIBS[external libs]
    end

    subgraph utils
    end

    SHA_C ---|dep| EXTLIBS
    SHA_C ---|dep| utils

```

## Utils details

```mermaid
flowchart TB
  subgraph utils
    UUID_C[uuid.c]
    FS_C[fsutil.c]
    UTILS_H[utils.h]

    FS_C -->|implements| UTILS_H
    UUID_C -->|implements| UTILS_H
  end

```

## Storage details

```mermaid
flowchart LR
  %% Storage DBIs (LMDB)
  subgraph USERS[Users]
    U1[user_id2data id:UserPacked]
    U2[user_mail2id mail:id]
    U3[user_id2pwd id:UserPwdHash]
  end

  subgraph SESSIONS[Sessions]
    SA[session_access key: key32 val: AccessRec]
    SR[session_refresh key: key32 val: RefreshRec]
    SX[session_revoked key: user_id val: revoked_since]
  end

  %% Relationships
  U2 -->|maps to| U1
  U3 -->|credentials for| U1
  SA -->|belongs to| U1
  SR -->|belongs to| U1
  SX -->|cutoff for| U1

```

```mermaid
erDiagram
  USER_ID2DATA {
    uint8_t ver
    uint8_t role
    uint8_t email_len
    char[] email
  }
  USER_MAIL2ID {
    string email
    uint8 id[16]
  }
  USER_ID2PWD {
    char blob[128]
    uint8 algo_ver
    uint64 created
    uint64 last_change
  }

  SESSION_ACCESS {
    uint8 user_id[16]
    uint64 exp
    uint64 created
    uint64 last_seen
    uint32 flags
  }
  SESSION_REFRESH {
    uint8 user_id[16]
    uint64 exp
    uint64 created
    uint8 rotated
  }
  SESSION_REVOKED {
    uint8 user_id[16]
    uint64 revoked_since
  }

  USER_MAIL2ID ||--|| USER_ID2DATA : maps_to
  USER_ID2PWD ||--|| USER_ID2DATA : credentials_for
  SESSION_ACCESS }|..|| USER_ID2DATA : belongs_to
  SESSION_REFRESH }|..|| USER_ID2DATA : belongs_to
  SESSION_REVOKED }|..|| USER_ID2DATA : marks_since
```

**Layering rule:** `main → (auth, db)`. Auth may call **db\_interface** only; DB never includes auth headers. Crypto helpers are leaf utilities.

---
