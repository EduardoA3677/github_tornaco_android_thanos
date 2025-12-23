.class public abstract Llyiahf/vczjk/yn2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "EnqueueRunnable"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/yn2;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/dqa;)Z
    .locals 24

    move-object/from16 v0, p0

    invoke-static {v0}, Llyiahf/vczjk/dqa;->Oooo000(Llyiahf/vczjk/dqa;)Ljava/util/HashSet;

    move-result-object v1

    const/4 v2, 0x0

    new-array v3, v2, [Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/util/HashSet;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Ljava/lang/String;

    iget-object v3, v0, Llyiahf/vczjk/dqa;->OooO0OO:Llyiahf/vczjk/oqa;

    iget-object v4, v3, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object v4, v4, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v4

    if-eqz v1, :cond_0

    array-length v7, v1

    if-lez v7, :cond_0

    const/4 v7, 0x1

    goto :goto_0

    :cond_0
    move v7, v2

    :goto_0
    sget-object v8, Llyiahf/vczjk/lqa;->OooOOOO:Llyiahf/vczjk/lqa;

    sget-object v9, Llyiahf/vczjk/lqa;->OooOOo:Llyiahf/vczjk/lqa;

    sget-object v10, Llyiahf/vczjk/lqa;->OooOOOo:Llyiahf/vczjk/lqa;

    iget-object v11, v3, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    if-eqz v7, :cond_5

    array-length v12, v1

    move v13, v2

    move v15, v13

    move/from16 v16, v15

    const/4 v14, 0x1

    :goto_1
    if-ge v13, v12, :cond_6

    aget-object v2, v1, v13

    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v6

    invoke-virtual {v6, v2}, Llyiahf/vczjk/bra;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/ara;

    move-result-object v6

    if-nez v6, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    const-string v3, "Prerequisite "

    const-string v4, " doesn\'t exist; not enqueuing"

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/yn2;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/o55;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    const/4 v2, 0x0

    :goto_2
    const/4 v1, 0x1

    goto/16 :goto_c

    :cond_1
    iget-object v2, v6, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    if-ne v2, v8, :cond_2

    const/4 v6, 0x1

    goto :goto_3

    :cond_2
    const/4 v6, 0x0

    :goto_3
    and-int/2addr v14, v6

    if-ne v2, v10, :cond_3

    const/16 v16, 0x1

    goto :goto_4

    :cond_3
    if-ne v2, v9, :cond_4

    const/4 v15, 0x1

    :cond_4
    :goto_4
    add-int/lit8 v13, v13, 0x1

    const/4 v2, 0x0

    goto :goto_1

    :cond_5
    const/4 v14, 0x1

    const/4 v15, 0x0

    const/16 v16, 0x0

    :cond_6
    const/4 v2, 0x0

    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v6

    sget-object v8, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    if-nez v6, :cond_8

    if-eqz v7, :cond_7

    goto :goto_5

    :cond_7
    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "SELECT id, state FROM workspec WHERE id IN (SELECT work_spec_id FROM workname WHERE name=?)"

    const/4 v1, 0x1

    invoke-static {v1, v0}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/xu7;->OooOOO0(ILjava/lang/String;)V

    throw v2

    :cond_8
    :goto_5
    iget-object v12, v0, Llyiahf/vczjk/dqa;->OooO0Oo:Ljava/util/List;

    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v12

    const/4 v13, 0x0

    :goto_6
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    move-result v17

    if-eqz v17, :cond_13

    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v17

    move-object/from16 v2, v17

    check-cast v2, Llyiahf/vczjk/yqa;

    move/from16 v17, v6

    iget-object v6, v2, Llyiahf/vczjk/yqa;->OooO0O0:Llyiahf/vczjk/ara;

    if-eqz v7, :cond_b

    if-nez v14, :cond_b

    if-eqz v16, :cond_9

    iput-object v10, v6, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    :goto_7
    move/from16 v18, v7

    goto :goto_8

    :cond_9
    if-eqz v15, :cond_a

    iput-object v9, v6, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    goto :goto_7

    :cond_a
    move/from16 v18, v7

    sget-object v7, Llyiahf/vczjk/lqa;->OooOOo0:Llyiahf/vczjk/lqa;

    iput-object v7, v6, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    goto :goto_8

    :cond_b
    move/from16 v18, v7

    iput-wide v4, v6, Llyiahf/vczjk/ara;->OooOOO:J

    :goto_8
    iget-object v7, v6, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    if-ne v7, v8, :cond_c

    const/4 v13, 0x1

    :cond_c
    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v7

    move-wide/from16 v19, v4

    const-string v4, "schedulers"

    iget-object v5, v3, Llyiahf/vczjk/oqa;->OooOOOo:Ljava/util/List;

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v4, v6, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    const-string v5, "androidx.work.multiprocess.RemoteListenableDelegatingWorker.ARGUMENT_REMOTE_LISTENABLE_WORKER_NAME"

    invoke-virtual {v4, v5}, Llyiahf/vczjk/mw1;->OooO0O0(Ljava/lang/String;)Z

    move-result v4

    move-object/from16 v21, v3

    iget-object v3, v6, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    move/from16 v22, v4

    const-string v4, "androidx.work.impl.workers.RemoteListenableWorker.ARGUMENT_PACKAGE_NAME"

    invoke-virtual {v3, v4}, Llyiahf/vczjk/mw1;->OooO0O0(Ljava/lang/String;)Z

    move-result v3

    iget-object v4, v6, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    move/from16 v23, v3

    const-string v3, "androidx.work.impl.workers.RemoteListenableWorker.ARGUMENT_CLASS_NAME"

    invoke-virtual {v4, v3}, Llyiahf/vczjk/mw1;->OooO0O0(Ljava/lang/String;)Z

    move-result v3

    const-string v4, "data"

    if-nez v22, :cond_d

    if-eqz v23, :cond_d

    if-eqz v3, :cond_d

    new-instance v3, Llyiahf/vczjk/tqa;

    move-object/from16 v22, v8

    const/16 v8, 0xe

    invoke-direct {v3, v8}, Llyiahf/vczjk/tqa;-><init>(I)V

    iget-object v8, v6, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    invoke-static {v8, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v8, v8, Llyiahf/vczjk/mw1;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {v3, v8}, Llyiahf/vczjk/tqa;->OooO0oO(Ljava/util/HashMap;)V

    iget-object v8, v6, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    iget-object v3, v3, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v3, Ljava/util/LinkedHashMap;

    invoke-interface {v3, v5, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v5, Llyiahf/vczjk/mw1;

    invoke-direct {v5, v3}, Llyiahf/vczjk/mw1;-><init>(Ljava/util/LinkedHashMap;)V

    invoke-static {v5}, Llyiahf/vczjk/nqa;->OoooO0O(Llyiahf/vczjk/mw1;)[B

    const-string v3, "androidx.work.multiprocess.RemoteListenableDelegatingWorker"

    invoke-static {v6, v3, v5}, Llyiahf/vczjk/ara;->OooO0O0(Llyiahf/vczjk/ara;Ljava/lang/String;Llyiahf/vczjk/mw1;)Llyiahf/vczjk/ara;

    move-result-object v6

    goto :goto_9

    :cond_d
    move-object/from16 v22, v8

    :goto_9
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1a

    if-ge v3, v5, :cond_f

    const-class v3, Landroidx/work/impl/workers/ConstraintTrackingWorker;

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v5

    iget-object v8, v6, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    invoke-static {v8, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_f

    iget-object v5, v6, Llyiahf/vczjk/ara;->OooOO0:Llyiahf/vczjk/qk1;

    move-object/from16 v23, v3

    iget-boolean v3, v5, Llyiahf/vczjk/qk1;->OooO0o0:Z

    if-nez v3, :cond_e

    iget-boolean v3, v5, Llyiahf/vczjk/qk1;->OooO0o:Z

    if-eqz v3, :cond_f

    :cond_e
    new-instance v3, Llyiahf/vczjk/tqa;

    const/16 v5, 0xe

    invoke-direct {v3, v5}, Llyiahf/vczjk/tqa;-><init>(I)V

    iget-object v5, v6, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v4, v5, Llyiahf/vczjk/mw1;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/tqa;->OooO0oO(Ljava/util/HashMap;)V

    iget-object v3, v3, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v3, Ljava/util/LinkedHashMap;

    const-string v4, "androidx.work.impl.workers.ConstraintTrackingWorker.ARGUMENT_CLASS_NAME"

    invoke-interface {v3, v4, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v4, Llyiahf/vczjk/mw1;

    invoke-direct {v4, v3}, Llyiahf/vczjk/mw1;-><init>(Ljava/util/LinkedHashMap;)V

    invoke-static {v4}, Llyiahf/vczjk/nqa;->OoooO0O(Llyiahf/vczjk/mw1;)[B

    invoke-virtual/range {v23 .. v23}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-static {v6, v3, v4}, Llyiahf/vczjk/ara;->OooO0O0(Llyiahf/vczjk/ara;Ljava/lang/String;Llyiahf/vczjk/mw1;)Llyiahf/vczjk/ara;

    move-result-object v6

    :cond_f
    iget-object v3, v7, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->beginTransaction()V

    :try_start_0
    iget-object v4, v7, Llyiahf/vczjk/bra;->OooO0O0:Llyiahf/vczjk/m62;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/m62;->OooO0oo(Ljava/lang/Object;)V

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->endTransaction()V

    const-string v3, "id.toString()"

    iget-object v4, v2, Llyiahf/vczjk/yqa;->OooO00o:Ljava/util/UUID;

    if-eqz v18, :cond_10

    array-length v5, v1

    const/4 v6, 0x0

    :goto_a
    if-ge v6, v5, :cond_10

    aget-object v7, v1, v6

    new-instance v8, Llyiahf/vczjk/k62;

    move-object/from16 v23, v1

    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v8, v1, v7}, Llyiahf/vczjk/k62;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO0O0()Llyiahf/vczjk/n62;

    move-result-object v1

    iget-object v7, v1, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v7, Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v7}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    invoke-virtual {v7}, Llyiahf/vczjk/ru7;->beginTransaction()V

    :try_start_1
    iget-object v1, v1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/m62;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/m62;->OooO0oo(Ljava/lang/Object;)V

    invoke-virtual {v7}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {v7}, Llyiahf/vczjk/ru7;->endTransaction()V

    add-int/lit8 v6, v6, 0x1

    move-object/from16 v1, v23

    goto :goto_a

    :catchall_0
    move-exception v0

    invoke-virtual {v7}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0

    :cond_10
    move-object/from16 v23, v1

    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO()Llyiahf/vczjk/era;

    move-result-object v1

    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v2, Llyiahf/vczjk/yqa;->OooO0OO:Ljava/util/Set;

    const-string v6, "tags"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/lang/Iterable;

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_11

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/String;

    new-instance v7, Llyiahf/vczjk/dra;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/dra;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v6, v1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v6, Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v6}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    invoke-virtual {v6}, Llyiahf/vczjk/ru7;->beginTransaction()V

    :try_start_2
    iget-object v8, v1, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/m62;

    invoke-virtual {v8, v7}, Llyiahf/vczjk/m62;->OooO0oo(Ljava/lang/Object;)V

    invoke-virtual {v6}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    invoke-virtual {v6}, Llyiahf/vczjk/ru7;->endTransaction()V

    goto :goto_b

    :catchall_1
    move-exception v0

    invoke-virtual {v6}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0

    :cond_11
    if-eqz v17, :cond_12

    move/from16 v6, v17

    move/from16 v7, v18

    move-wide/from16 v4, v19

    move-object/from16 v3, v21

    move-object/from16 v8, v22

    move-object/from16 v1, v23

    const/4 v2, 0x0

    goto/16 :goto_6

    :cond_12
    invoke-virtual {v11}, Landroidx/work/impl/WorkDatabase;->OooO0o()Llyiahf/vczjk/tqa;

    invoke-virtual {v4}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :catchall_2
    move-exception v0

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0

    :cond_13
    move v2, v13

    goto/16 :goto_2

    :goto_c
    iput-boolean v1, v0, Llyiahf/vczjk/dqa;->OooO0oO:Z

    return v2
.end method
