.class public final Llyiahf/vczjk/oqa;
.super Llyiahf/vczjk/nqa;
.source "SourceFile"


# static fields
.field public static final OooOo:Ljava/lang/Object;

.field public static OooOo0O:Llyiahf/vczjk/oqa;

.field public static OooOo0o:Llyiahf/vczjk/oqa;


# instance fields
.field public final OooOO0o:Landroid/content/Context;

.field public final OooOOO:Landroidx/work/impl/WorkDatabase;

.field public final OooOOO0:Llyiahf/vczjk/wh1;

.field public final OooOOOO:Llyiahf/vczjk/rqa;

.field public final OooOOOo:Ljava/util/List;

.field public final OooOOo:Llyiahf/vczjk/tqa;

.field public final OooOOo0:Llyiahf/vczjk/n77;

.field public OooOOoo:Z

.field public final OooOo0:Llyiahf/vczjk/qx9;

.field public OooOo00:Landroid/content/BroadcastReceiver$PendingResult;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "WorkManagerImpl"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    const/4 v0, 0x0

    sput-object v0, Llyiahf/vczjk/oqa;->OooOo0O:Llyiahf/vczjk/oqa;

    sput-object v0, Llyiahf/vczjk/oqa;->OooOo0o:Llyiahf/vczjk/oqa;

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/oqa;->OooOo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/rqa;Landroidx/work/impl/WorkDatabase;Ljava/util/List;Llyiahf/vczjk/n77;Llyiahf/vczjk/qx9;)V
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v0, p2

    move-object/from16 v2, p3

    move-object/from16 v3, p4

    move-object/from16 v4, p5

    move-object/from16 v5, p6

    const/4 v6, 0x3

    const/4 v7, 0x2

    const/4 v8, 0x0

    const/4 v9, 0x1

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-boolean v8, v1, Llyiahf/vczjk/oqa;->OooOOoo:Z

    invoke-virtual/range {p1 .. p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v10

    invoke-virtual {v10}, Landroid/content/Context;->isDeviceProtectedStorage()Z

    move-result v11

    if-nez v11, :cond_4

    new-instance v11, Llyiahf/vczjk/o55;

    iget v12, v0, Llyiahf/vczjk/wh1;->OooO0oo:I

    invoke-direct {v11, v12}, Llyiahf/vczjk/o55;-><init>(I)V

    sget-object v12, Llyiahf/vczjk/o55;->OooOOO:Ljava/lang/Object;

    monitor-enter v12

    :try_start_0
    sget-object v13, Llyiahf/vczjk/o55;->OooOOOO:Llyiahf/vczjk/o55;

    if-nez v13, :cond_0

    sput-object v11, Llyiahf/vczjk/o55;->OooOOOO:Llyiahf/vczjk/o55;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto/16 :goto_2

    :cond_0
    :goto_0
    monitor-exit v12
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iput-object v10, v1, Llyiahf/vczjk/oqa;->OooOO0o:Landroid/content/Context;

    iput-object v2, v1, Llyiahf/vczjk/oqa;->OooOOOO:Llyiahf/vczjk/rqa;

    iput-object v3, v1, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    iput-object v5, v1, Llyiahf/vczjk/oqa;->OooOOo0:Llyiahf/vczjk/n77;

    move-object/from16 v11, p7

    iput-object v11, v1, Llyiahf/vczjk/oqa;->OooOo0:Llyiahf/vczjk/qx9;

    iput-object v0, v1, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iput-object v4, v1, Llyiahf/vczjk/oqa;->OooOOOo:Ljava/util/List;

    const-string v11, "taskExecutor.taskCoroutineDispatcher"

    iget-object v12, v2, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    invoke-static {v12, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v11

    new-instance v12, Llyiahf/vczjk/tqa;

    const/16 v13, 0x1b

    invoke-direct {v12, v3, v13}, Llyiahf/vczjk/tqa;-><init>(Ljava/lang/Object;I)V

    iput-object v12, v1, Llyiahf/vczjk/oqa;->OooOOo:Llyiahf/vczjk/tqa;

    iget-object v12, v2, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    sget-object v13, Llyiahf/vczjk/t88;->OooO00o:Ljava/lang/String;

    new-instance v13, Llyiahf/vczjk/m88;

    invoke-direct {v13, v12, v4, v0, v3}, Llyiahf/vczjk/m88;-><init>(Ljava/util/concurrent/Executor;Ljava/util/List;Llyiahf/vczjk/wh1;Landroidx/work/impl/WorkDatabase;)V

    invoke-virtual {v5, v13}, Llyiahf/vczjk/n77;->OooO00o(Llyiahf/vczjk/gs2;)V

    new-instance v4, Llyiahf/vczjk/pb3;

    invoke-direct {v4, v10, v1}, Llyiahf/vczjk/pb3;-><init>(Landroid/content/Context;Llyiahf/vczjk/oqa;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/rqa;->OooO00o(Ljava/lang/Runnable;)V

    sget-object v2, Llyiahf/vczjk/q8a;->OooO00o:Ljava/lang/String;

    invoke-static {v10, v0}, Llyiahf/vczjk/m77;->OooO00o(Landroid/content/Context;Llyiahf/vczjk/wh1;)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {v3}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "SELECT COUNT(*) > 0 FROM workspec WHERE state NOT IN (2, 3, 5) LIMIT 1"

    invoke-static {v8, v2}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v2

    const-string v3, "workspec"

    filled-new-array {v3}, [Ljava/lang/String;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/rw7;

    invoke-direct {v4, v0, v2, v7}, Llyiahf/vczjk/rw7;-><init>(Ljava/lang/Object;Llyiahf/vczjk/xu7;I)V

    iget-object v0, v0, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    new-instance v2, Llyiahf/vczjk/o000OO;

    const/16 v5, 0x14

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->getInvalidationTracker()Llyiahf/vczjk/q44;

    move-result-object v4

    invoke-static {v3, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v3

    check-cast v3, [Ljava/lang/String;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v5, "tables"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v5, v4, Llyiahf/vczjk/q44;->OooO0OO:Llyiahf/vczjk/b1a;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/b1a;->OooO0oO([Ljava/lang/String;)Llyiahf/vczjk/xn6;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, [Ljava/lang/String;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, [I

    const-string v13, "resolvedTableNames"

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v13, "tableIds"

    invoke-static {v3, v13}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v13, Llyiahf/vczjk/r0a;

    const/4 v14, 0x0

    const/4 v15, 0x1

    move-object/from16 p3, v3

    move-object/from16 p2, v5

    move-object/from16 p5, v12

    move-object/from16 p1, v13

    move-object/from16 p6, v14

    move/from16 p4, v15

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/r0a;-><init>(Llyiahf/vczjk/b1a;[IZ[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    move-object/from16 v3, p1

    new-instance v5, Llyiahf/vczjk/s48;

    invoke-direct {v5, v3}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    iget-object v3, v4, Llyiahf/vczjk/q44;->OooO:Llyiahf/vczjk/gq5;

    const/4 v4, 0x0

    if-eqz v3, :cond_1

    iget-object v3, v3, Llyiahf/vczjk/gq5;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance v13, Llyiahf/vczjk/x63;

    invoke-direct {v13, v6, v3, v12}, Llyiahf/vczjk/x63;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    move-object v13, v4

    :goto_1
    if-eqz v13, :cond_2

    new-array v3, v7, [Llyiahf/vczjk/f43;

    aput-object v5, v3, v8

    aput-object v13, v3, v9

    sget v5, Llyiahf/vczjk/e63;->OooO00o:I

    invoke-static {v3}, Llyiahf/vczjk/sy;->OooooOo([Ljava/lang/Object;)Ljava/lang/Iterable;

    move-result-object v3

    new-instance v5, Llyiahf/vczjk/gt0;

    sget-object v7, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    sget-object v8, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    const/4 v12, -0x2

    invoke-direct {v5, v3, v7, v12, v8}, Llyiahf/vczjk/gt0;-><init>(Ljava/lang/Iterable;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    :cond_2
    const/4 v3, -0x1

    invoke-static {v5, v3}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object v5

    new-instance v7, Llyiahf/vczjk/y63;

    invoke-direct {v7, v5, v0, v2}, Llyiahf/vczjk/y63;-><init>(Llyiahf/vczjk/f43;Landroidx/work/impl/WorkDatabase_Impl;Llyiahf/vczjk/o000OO;)V

    new-instance v0, Llyiahf/vczjk/o8a;

    const/4 v2, 0x4

    invoke-direct {v0, v2, v4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v2, Llyiahf/vczjk/s53;

    invoke-direct {v2, v7, v0}, Llyiahf/vczjk/s53;-><init>(Llyiahf/vczjk/y63;Llyiahf/vczjk/o8a;)V

    invoke-static {v2, v3}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/p8a;

    invoke-direct {v2, v10, v4}, Llyiahf/vczjk/p8a;-><init>(Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/w53;

    invoke-direct {v3, v0, v2, v9}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    new-instance v0, Llyiahf/vczjk/a53;

    invoke-direct {v0, v3, v4}, Llyiahf/vczjk/a53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    invoke-static {v11, v4, v4, v0, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_3
    return-void

    :goto_2
    :try_start_1
    monitor-exit v12
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0

    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "Cannot initialize WorkManager in direct boot mode"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OoooOoo(Landroid/content/Context;)Llyiahf/vczjk/oqa;
    .locals 2

    sget-object v0, Llyiahf/vczjk/oqa;->OooOo:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    sget-object v1, Llyiahf/vczjk/oqa;->OooOo0O:Llyiahf/vczjk/oqa;

    if-eqz v1, :cond_0

    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    sget-object v1, Llyiahf/vczjk/oqa;->OooOo0o:Llyiahf/vczjk/oqa;

    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_0
    if-eqz v1, :cond_1

    :try_start_2
    monitor-exit v0

    return-object v1

    :catchall_1
    move-exception p0

    goto :goto_2

    :cond_1
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v1, "WorkManager is not initialized properly.  You have explicitly disabled WorkManagerInitializer in your manifest, have not manually called WorkManager#initialize at this point, and your Application does not implement Configuration.Provider."

    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_1
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :try_start_4
    throw p0

    :goto_2
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    throw p0
.end method


# virtual methods
.method public final OoooOoO(Ljava/util/UUID;)Llyiahf/vczjk/ee6;
    .locals 3

    const-string v0, "id"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object v0, v0, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    iget-object v1, p0, Llyiahf/vczjk/oqa;->OooOOOO:Llyiahf/vczjk/rqa;

    iget-object v1, v1, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    const-string v2, "workManagerImpl.workTask\u2026ecutor.serialTaskExecutor"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/qp0;

    invoke-direct {v2, p0, p1}, Llyiahf/vczjk/qp0;-><init>(Llyiahf/vczjk/oqa;Ljava/util/UUID;)V

    const-string p1, "CancelWorkById"

    invoke-static {v0, p1, v1, v2}, Llyiahf/vczjk/cp7;->Oooo000(Llyiahf/vczjk/e86;Ljava/lang/String;Ljava/util/concurrent/Executor;Llyiahf/vczjk/le3;)Llyiahf/vczjk/ee6;

    move-result-object p1

    return-object p1
.end method

.method public final Ooooo00()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/oqa;->OooOo:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x1

    :try_start_0
    iput-boolean v1, p0, Llyiahf/vczjk/oqa;->OooOOoo:Z

    iget-object v1, p0, Llyiahf/vczjk/oqa;->OooOo00:Landroid/content/BroadcastReceiver$PendingResult;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Landroid/content/BroadcastReceiver$PendingResult;->finish()V

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/oqa;->OooOo00:Landroid/content/BroadcastReceiver$PendingResult;

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method

.method public final Ooooo0o()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object v0, v0, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    const-string v1, "ReschedulingWork"

    new-instance v2, Llyiahf/vczjk/ku7;

    const/16 v3, 0x14

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    const-string v3, "<this>"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/ll6;->OooOO0()Z

    move-result v0

    if-eqz v0, :cond_0

    :try_start_0
    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/ku7;->OooO00o()Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_1

    invoke-static {}, Landroid/os/Trace;->endSection()V

    :cond_1
    return-void

    :catchall_0
    move-exception v1

    if-eqz v0, :cond_2

    invoke-static {}, Landroid/os/Trace;->endSection()V

    :cond_2
    throw v1
.end method
