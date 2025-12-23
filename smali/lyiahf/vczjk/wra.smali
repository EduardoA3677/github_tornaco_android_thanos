.class public final Llyiahf/vczjk/wra;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/bra;

.field public final OooO00o:Llyiahf/vczjk/ara;

.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Ljava/lang/String;

.field public final OooO0Oo:Llyiahf/vczjk/rqa;

.field public final OooO0o:Llyiahf/vczjk/vp3;

.field public final OooO0o0:Llyiahf/vczjk/wh1;

.field public final OooO0oO:Llyiahf/vczjk/n77;

.field public final OooO0oo:Landroidx/work/impl/WorkDatabase;

.field public final OooOO0:Llyiahf/vczjk/n62;

.field public final OooOO0O:Ljava/util/ArrayList;

.field public final OooOO0o:Ljava/lang/String;

.field public final OooOOO0:Llyiahf/vczjk/x74;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ex9;)V
    .locals 7

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/ex9;->OooOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ara;

    iput-object v0, p0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget-object v1, p1, Llyiahf/vczjk/ex9;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Landroid/content/Context;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0O0:Landroid/content/Context;

    iget-object v0, v0, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    iget-object v1, p1, Llyiahf/vczjk/ex9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rqa;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0Oo:Llyiahf/vczjk/rqa;

    iget-object v1, p1, Llyiahf/vczjk/ex9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wh1;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0o0:Llyiahf/vczjk/wh1;

    iget-object v1, v1, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0o:Llyiahf/vczjk/vp3;

    iget-object v1, p1, Llyiahf/vczjk/ex9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/n77;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0oO:Llyiahf/vczjk/n77;

    iget-object v1, p1, Llyiahf/vczjk/ex9;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Landroidx/work/impl/WorkDatabase;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooO0oo:Landroidx/work/impl/WorkDatabase;

    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->OooO0O0()Llyiahf/vczjk/n62;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooOO0:Llyiahf/vczjk/n62;

    iget-object p1, p1, Llyiahf/vczjk/ex9;->OooOOoo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ljava/util/ArrayList;

    iput-object v1, p0, Llyiahf/vczjk/wra;->OooOO0O:Ljava/util/ArrayList;

    const-string p1, "Work [ id="

    const-string v2, ", tags={ "

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/ix8;->OooOOO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p1

    const/4 v4, 0x0

    const/16 v6, 0x3e

    const-string v2, ","

    const/4 v3, 0x0

    const/4 v5, 0x0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v0

    const-string v1, " } ]"

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wra;->OooOO0o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wra;->OooOOO0:Llyiahf/vczjk/x74;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/wra;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    const/4 v3, 0x1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v4, v0, Llyiahf/vczjk/tra;

    if-eqz v4, :cond_0

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/tra;

    iget v5, v4, Llyiahf/vczjk/tra;->label:I

    const/high16 v6, -0x80000000

    and-int v7, v5, v6

    if-eqz v7, :cond_0

    sub-int/2addr v5, v6

    iput v5, v4, Llyiahf/vczjk/tra;->label:I

    goto :goto_0

    :cond_0
    new-instance v4, Llyiahf/vczjk/tra;

    invoke-direct {v4, v1, v0}, Llyiahf/vczjk/tra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object v0, v4, Llyiahf/vczjk/tra;->result:Ljava/lang/Object;

    sget-object v5, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v6, v4, Llyiahf/vczjk/tra;->label:I

    if-eqz v6, :cond_2

    if-ne v6, v3, :cond_1

    iget-object v1, v4, Llyiahf/vczjk/tra;->L$1:Ljava/lang/Object;

    check-cast v1, Landroidx/work/WorkerParameters;

    iget-object v1, v4, Llyiahf/vczjk/tra;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wra;

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_8

    :catchall_0
    move-exception v0

    goto/16 :goto_9

    :catch_0
    move-exception v0

    goto/16 :goto_a

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v6, v1, Llyiahf/vczjk/wra;->OooO0o0:Llyiahf/vczjk/wh1;

    iget-object v0, v6, Llyiahf/vczjk/wh1;->OooOOO0:Llyiahf/vczjk/e86;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/ll6;->OooOO0()Z

    move-result v7

    iget-object v8, v1, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget-object v9, v8, Llyiahf/vczjk/ara;->OooOo:Ljava/lang/String;

    iget-object v10, v8, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    const/4 v11, 0x0

    if-eqz v7, :cond_5

    if-eqz v9, :cond_5

    invoke-virtual {v8}, Llyiahf/vczjk/ara;->hashCode()I

    move-result v0

    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v13, 0x1d

    if-lt v12, v13, :cond_3

    invoke-static {v9}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    invoke-static {v0, v12}, Llyiahf/vczjk/ox9;->OooO00o(ILjava/lang/String;)V

    goto :goto_3

    :cond_3
    invoke-static {v9}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    const-string v13, "asyncTraceBegin"

    :try_start_1
    sget-object v14, Llyiahf/vczjk/ll6;->OooO0o:Ljava/lang/reflect/Method;

    if-nez v14, :cond_4

    const-class v14, Landroid/os/Trace;

    sget-object v15, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    const-class v3, Ljava/lang/String;

    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    filled-new-array {v15, v3, v2}, [Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v14, v13, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/ll6;->OooO0o:Ljava/lang/reflect/Method;

    goto :goto_1

    :catch_1
    move-exception v0

    goto :goto_2

    :cond_4
    :goto_1
    sget-object v2, Llyiahf/vczjk/ll6;->OooO0o:Ljava/lang/reflect/Method;

    sget-wide v14, Llyiahf/vczjk/ll6;->OooO0Oo:J

    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {v3, v12, v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v2, v11, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_3

    :goto_2
    invoke-static {v13, v0}, Llyiahf/vczjk/ll6;->OooO0oO(Ljava/lang/String;Ljava/lang/Exception;)V

    :cond_5
    :goto_3
    new-instance v0, Llyiahf/vczjk/mra;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/mra;-><init>(Llyiahf/vczjk/wra;I)V

    iget-object v2, v1, Llyiahf/vczjk/wra;->OooO0oo:Landroidx/work/impl/WorkDatabase;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    const-string v3, "shouldExit"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_6

    new-instance v5, Llyiahf/vczjk/pra;

    invoke-direct {v5}, Llyiahf/vczjk/pra;-><init>()V

    goto/16 :goto_b

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/ara;->OooO0Oo()Z

    move-result v0

    iget-object v3, v1, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    if-eqz v0, :cond_7

    iget-object v0, v8, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    goto/16 :goto_7

    :cond_7
    iget-object v0, v6, Llyiahf/vczjk/wh1;->OooO0o:Llyiahf/vczjk/xj0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v12, v8, Llyiahf/vczjk/ara;->OooO0Oo:Ljava/lang/String;

    const-string v0, "className"

    invoke-static {v12, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/k04;->OooO00o:Ljava/lang/String;

    :try_start_2
    invoke-static {v12}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0, v11}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    move-result-object v0

    invoke-virtual {v0, v11}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const-string v13, "null cannot be cast to non-null type androidx.work.InputMerger"

    invoke-static {v0, v13}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Landroidx/work/OverwritingInputMerger;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    goto :goto_4

    :catch_2
    move-exception v0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v13

    const-string v14, "Trouble instantiating "

    invoke-virtual {v14, v12}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/k04;->OooO00o:Ljava/lang/String;

    invoke-virtual {v13, v15, v14, v0}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    move-object v0, v11

    :goto_4
    if-nez v0, :cond_8

    sget-object v0, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    const-string v2, "Could not create Input Merger "

    invoke-virtual {v2, v12}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/o55;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/nra;

    invoke-direct {v5}, Llyiahf/vczjk/nra;-><init>()V

    goto/16 :goto_b

    :cond_8
    iget-object v0, v8, Llyiahf/vczjk/ara;->OooO0o0:Llyiahf/vczjk/mw1;

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    iget-object v8, v1, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v12, "SELECT output FROM workspec WHERE id IN\n             (SELECT prerequisite_id FROM dependency WHERE work_spec_id=?)"

    const/4 v13, 0x1

    invoke-static {v13, v12}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v12

    invoke-virtual {v12, v13, v3}, Llyiahf/vczjk/xu7;->OooOOO0(ILjava/lang/String;)V

    iget-object v8, v8, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v8}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    const/4 v13, 0x0

    invoke-static {v8, v12, v13}, Llyiahf/vczjk/u34;->OoooO0O(Llyiahf/vczjk/ru7;Llyiahf/vczjk/ia9;Z)Landroid/database/Cursor;

    move-result-object v8

    :try_start_3
    new-instance v13, Ljava/util/ArrayList;

    invoke-interface {v8}, Landroid/database/Cursor;->getCount()I

    move-result v14

    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    :goto_5
    invoke-interface {v8}, Landroid/database/Cursor;->moveToNext()Z

    move-result v14

    if-eqz v14, :cond_9

    const/4 v14, 0x0

    invoke-interface {v8, v14}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v15

    invoke-static {v15}, Llyiahf/vczjk/mw1;->OooO00o([B)Llyiahf/vczjk/mw1;

    move-result-object v15

    invoke-virtual {v13, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_5

    :catchall_1
    move-exception v0

    goto/16 :goto_c

    :cond_9
    invoke-interface {v8}, Landroid/database/Cursor;->close()V

    invoke-virtual {v12}, Llyiahf/vczjk/xu7;->OooOo()V

    invoke-static {v13, v0}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    new-instance v8, Llyiahf/vczjk/tqa;

    const/16 v12, 0xe

    invoke-direct {v8, v12}, Llyiahf/vczjk/tqa;-><init>(I)V

    new-instance v12, Ljava/util/LinkedHashMap;

    invoke-direct {v12}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_a

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/mw1;

    iget-object v13, v13, Llyiahf/vczjk/mw1;->OooO00o:Ljava/util/HashMap;

    invoke-static {v13}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v13

    const-string v14, "unmodifiableMap(values)"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v12, v13}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    goto :goto_6

    :cond_a
    invoke-virtual {v8, v12}, Llyiahf/vczjk/tqa;->OooO0oO(Ljava/util/HashMap;)V

    new-instance v0, Llyiahf/vczjk/mw1;

    iget-object v8, v8, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v8, Ljava/util/LinkedHashMap;

    invoke-direct {v0, v8}, Llyiahf/vczjk/mw1;-><init>(Ljava/util/LinkedHashMap;)V

    invoke-static {v0}, Llyiahf/vczjk/nqa;->OoooO0O(Llyiahf/vczjk/mw1;)[B

    :goto_7
    new-instance v8, Landroidx/work/WorkerParameters;

    invoke-static {v3}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    move-result-object v3

    new-instance v12, Llyiahf/vczjk/vqa;

    new-instance v12, Llyiahf/vczjk/iqa;

    iget-object v13, v1, Llyiahf/vczjk/wra;->OooO0oO:Llyiahf/vczjk/n77;

    iget-object v14, v1, Llyiahf/vczjk/wra;->OooO0Oo:Llyiahf/vczjk/rqa;

    invoke-direct {v12, v2, v13, v14}, Llyiahf/vczjk/iqa;-><init>(Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/n77;Llyiahf/vczjk/rqa;)V

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    iput-object v3, v8, Landroidx/work/WorkerParameters;->OooO00o:Ljava/util/UUID;

    iput-object v0, v8, Landroidx/work/WorkerParameters;->OooO0O0:Llyiahf/vczjk/mw1;

    new-instance v0, Ljava/util/HashSet;

    iget-object v3, v1, Llyiahf/vczjk/wra;->OooOO0O:Ljava/util/ArrayList;

    invoke-direct {v0, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iget-object v0, v6, Llyiahf/vczjk/wh1;->OooO00o:Ljava/util/concurrent/ExecutorService;

    iput-object v0, v8, Landroidx/work/WorkerParameters;->OooO0OO:Ljava/util/concurrent/ExecutorService;

    iget-object v0, v6, Llyiahf/vczjk/wh1;->OooO0O0:Llyiahf/vczjk/q32;

    iput-object v0, v8, Landroidx/work/WorkerParameters;->OooO0Oo:Llyiahf/vczjk/qr1;

    iput-object v14, v8, Landroidx/work/WorkerParameters;->OooO0o0:Llyiahf/vczjk/rqa;

    iget-object v0, v6, Llyiahf/vczjk/wh1;->OooO0o0:Llyiahf/vczjk/ws7;

    iput-object v0, v8, Landroidx/work/WorkerParameters;->OooO0o:Llyiahf/vczjk/ws7;

    :try_start_4
    iget-object v3, v1, Llyiahf/vczjk/wra;->OooO0O0:Landroid/content/Context;

    invoke-virtual {v0, v3, v10, v8}, Llyiahf/vczjk/ws7;->OooO0oO(Landroid/content/Context;Ljava/lang/String;Landroidx/work/WorkerParameters;)Llyiahf/vczjk/b25;

    move-result-object v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    const/4 v13, 0x1

    iput-boolean v13, v0, Llyiahf/vczjk/b25;->OooO0Oo:Z

    invoke-interface {v4}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {v3, v6}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v3, Llyiahf/vczjk/v74;

    new-instance v6, Llyiahf/vczjk/ura;

    invoke-direct {v6, v0, v7, v9, v1}, Llyiahf/vczjk/ura;-><init>(Llyiahf/vczjk/b25;ZLjava/lang/String;Llyiahf/vczjk/wra;)V

    invoke-interface {v3, v6}, Llyiahf/vczjk/v74;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    new-instance v6, Llyiahf/vczjk/mra;

    const/4 v13, 0x1

    invoke-direct {v6, v1, v13}, Llyiahf/vczjk/mra;-><init>(Llyiahf/vczjk/wra;I)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    move-result-object v2

    const-string v6, "workDatabase.runInTransa\u2026e\n            }\n        )"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-nez v2, :cond_b

    new-instance v5, Llyiahf/vczjk/pra;

    invoke-direct {v5}, Llyiahf/vczjk/pra;-><init>()V

    goto/16 :goto_b

    :cond_b
    invoke-interface {v3}, Llyiahf/vczjk/v74;->isCancelled()Z

    move-result v2

    if-eqz v2, :cond_c

    new-instance v5, Llyiahf/vczjk/pra;

    invoke-direct {v5}, Llyiahf/vczjk/pra;-><init>()V

    goto/16 :goto_b

    :cond_c
    const-string v2, "workTaskExecutor.getMainThreadExecutor()"

    iget-object v3, v14, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/dn8;->OoooOo0(Ljava/util/concurrent/Executor;)Llyiahf/vczjk/qr1;

    move-result-object v2

    :try_start_5
    new-instance v3, Llyiahf/vczjk/vra;

    invoke-direct {v3, v1, v0, v12, v11}, Llyiahf/vczjk/vra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/b25;Llyiahf/vczjk/rb3;Llyiahf/vczjk/yo1;)V

    iput-object v1, v4, Llyiahf/vczjk/tra;->L$0:Ljava/lang/Object;

    iput-object v8, v4, Llyiahf/vczjk/tra;->L$1:Ljava/lang/Object;

    const/4 v13, 0x1

    iput v13, v4, Llyiahf/vczjk/tra;->label:I

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v5, :cond_d

    goto :goto_b

    :cond_d
    :goto_8
    check-cast v0, Llyiahf/vczjk/a25;

    new-instance v5, Llyiahf/vczjk/ora;

    const-string v2, "result"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v5, v0}, Llyiahf/vczjk/ora;-><init>(Llyiahf/vczjk/a25;)V
    :try_end_5
    .catch Ljava/util/concurrent/CancellationException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    goto :goto_b

    :goto_9
    sget-object v2, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, v1, Llyiahf/vczjk/wra;->OooOO0o:Ljava/lang/String;

    const-string v5, " failed because it threw an exception/error"

    invoke-static {v4, v1, v5}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v2, v1, v0}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    new-instance v5, Llyiahf/vczjk/nra;

    invoke-direct {v5}, Llyiahf/vczjk/nra;-><init>()V

    goto :goto_b

    :goto_a
    sget-object v2, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, v1, Llyiahf/vczjk/wra;->OooOO0o:Ljava/lang/String;

    const-string v5, " was cancelled"

    invoke-static {v4, v1, v5}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    iget v3, v3, Llyiahf/vczjk/o55;->OooOOO0:I

    const/4 v4, 0x4

    if-gt v3, v4, :cond_e

    invoke-static {v2, v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_e
    throw v0

    :catchall_2
    sget-object v0, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Could not create Worker "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/o55;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/nra;

    invoke-direct {v5}, Llyiahf/vczjk/nra;-><init>()V

    :goto_b
    return-object v5

    :goto_c
    invoke-interface {v8}, Landroid/database/Cursor;->close()V

    invoke-virtual {v12}, Llyiahf/vczjk/xu7;->OooOo()V

    throw v0
.end method


# virtual methods
.method public final OooO0O0(I)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    iget-object v1, p0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    iget-object v2, p0, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/bra;->OooOO0o(Llyiahf/vczjk/lqa;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wra;->OooO0o:Llyiahf/vczjk/vp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-virtual {v1, v3, v4, v2}, Llyiahf/vczjk/bra;->OooOO0(JLjava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget v0, v0, Llyiahf/vczjk/ara;->OooOo0O:I

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/bra;->OooO(ILjava/lang/String;)V

    const-wide/16 v3, -0x1

    invoke-virtual {v1, v3, v4, v2}, Llyiahf/vczjk/bra;->OooO0oo(JLjava/lang/String;)V

    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/bra;->OooOOO0(ILjava/lang/String;)V

    return-void
.end method

.method public final OooO0OO()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/wra;->OooO0o:Llyiahf/vczjk/vp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    iget-object v3, p0, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v2, v0, v1, v3}, Llyiahf/vczjk/bra;->OooOO0(JLjava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    invoke-virtual {v2, v0, v3}, Llyiahf/vczjk/bra;->OooOO0o(Llyiahf/vczjk/lqa;Ljava/lang/String;)V

    iget-object v0, v2, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    iget-object v1, v2, Llyiahf/vczjk/bra;->OooO:Llyiahf/vczjk/qw7;

    invoke-virtual {v1}, Llyiahf/vczjk/yd7;->OooO00o()Llyiahf/vczjk/la9;

    move-result-object v4

    const/4 v5, 0x1

    invoke-interface {v4, v5, v3}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->beginTransaction()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :try_start_1
    invoke-interface {v4}, Llyiahf/vczjk/la9;->OooOOOo()I

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    :try_start_2
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->endTransaction()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    invoke-virtual {v1, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    iget-object v1, p0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget v1, v1, Llyiahf/vczjk/ara;->OooOo0O:I

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/bra;->OooO(ILjava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    iget-object v1, v2, Llyiahf/vczjk/bra;->OooO0o0:Llyiahf/vczjk/qw7;

    invoke-virtual {v1}, Llyiahf/vczjk/yd7;->OooO00o()Llyiahf/vczjk/la9;

    move-result-object v4

    invoke-interface {v4, v5, v3}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :try_start_3
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->beginTransaction()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :try_start_4
    invoke-interface {v4}, Llyiahf/vczjk/la9;->OooOOOo()I

    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    :try_start_5
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->endTransaction()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    invoke-virtual {v1, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    const-wide/16 v0, -0x1

    invoke-virtual {v2, v0, v1, v3}, Llyiahf/vczjk/bra;->OooO0oo(JLjava/lang/String;)V

    return-void

    :catchall_0
    move-exception v0

    goto :goto_0

    :catchall_1
    move-exception v2

    :try_start_6
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    :goto_0
    invoke-virtual {v1, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    throw v0

    :catchall_2
    move-exception v0

    goto :goto_1

    :catchall_3
    move-exception v2

    :try_start_7
    invoke-virtual {v0}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    :goto_1
    invoke-virtual {v1, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    throw v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/a25;)V
    .locals 6

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/e21;->OoooO0([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v1

    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    if-nez v2, :cond_1

    invoke-static {v1}, Llyiahf/vczjk/j21;->OooooOO(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/bra;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/lqa;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/lqa;->OooOOo:Llyiahf/vczjk/lqa;

    if-eq v4, v5, :cond_0

    sget-object v4, Llyiahf/vczjk/lqa;->OooOOOo:Llyiahf/vczjk/lqa;

    invoke-virtual {v3, v4, v2}, Llyiahf/vczjk/bra;->OooOO0o(Llyiahf/vczjk/lqa;Ljava/lang/String;)V

    :cond_0
    iget-object v3, p0, Llyiahf/vczjk/wra;->OooOO0:Llyiahf/vczjk/n62;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/n62;->o0O0O00(Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/x15;

    iget-object p1, p1, Llyiahf/vczjk/x15;->OooO00o:Llyiahf/vczjk/mw1;

    const-string v1, "failure.outputData"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget v1, v1, Llyiahf/vczjk/ara;->OooOo0O:I

    invoke-virtual {v3, v1, v0}, Llyiahf/vczjk/bra;->OooO(ILjava/lang/String;)V

    invoke-virtual {v3, v0, p1}, Llyiahf/vczjk/bra;->OooOO0O(Ljava/lang/String;Llyiahf/vczjk/mw1;)V

    return-void
.end method
