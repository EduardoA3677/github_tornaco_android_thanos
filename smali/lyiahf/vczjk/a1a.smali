.class public final Llyiahf/vczjk/a1a;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/b1a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/a1a;->this$0:Llyiahf/vczjk/b1a;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/a1a;

    iget-object v1, p0, Llyiahf/vczjk/a1a;->this$0:Llyiahf/vczjk/b1a;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/a1a;-><init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/a1a;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ay9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/a1a;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/a1a;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/a1a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v1, p0

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v1, Llyiahf/vczjk/a1a;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x1

    const/4 v5, 0x2

    if-eqz v2, :cond_2

    if-eq v2, v4, :cond_1

    if-ne v2, v5, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v3

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object v2, v1, Llyiahf/vczjk/a1a;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ay9;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v6, p1

    goto :goto_0

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v1, Llyiahf/vczjk/a1a;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ay9;

    iput-object v2, v1, Llyiahf/vczjk/a1a;->L$0:Ljava/lang/Object;

    iput v4, v1, Llyiahf/vczjk/a1a;->label:I

    invoke-interface {v2, v1}, Llyiahf/vczjk/ay9;->OooO0OO(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v0, :cond_3

    goto/16 :goto_7

    :cond_3
    :goto_0
    check-cast v6, Ljava/lang/Boolean;

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    if-eqz v6, :cond_4

    goto/16 :goto_8

    :cond_4
    iget-object v6, v1, Llyiahf/vczjk/a1a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v6, v6, Llyiahf/vczjk/b1a;->OooO0oo:Llyiahf/vczjk/zu1;

    iget-object v7, v6, Llyiahf/vczjk/zu1;->OooO0OO:Ljava/lang/Object;

    check-cast v7, [J

    iget-object v8, v6, Llyiahf/vczjk/zu1;->OooO0O0:Ljava/lang/Object;

    check-cast v8, Ljava/util/concurrent/locks/ReentrantLock;

    invoke-virtual {v8}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    :try_start_0
    iget-boolean v9, v6, Llyiahf/vczjk/zu1;->OooO00o:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v10, 0x0

    if-nez v9, :cond_5

    invoke-virtual {v8}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    move-object v12, v10

    goto :goto_6

    :cond_5
    const/4 v9, 0x0

    :try_start_1
    iput-boolean v9, v6, Llyiahf/vczjk/zu1;->OooO00o:Z

    array-length v11, v7

    new-array v12, v11, [Llyiahf/vczjk/g86;

    move v13, v9

    move v14, v13

    :goto_1
    if-ge v13, v11, :cond_9

    aget-wide v15, v7, v13

    const-wide/16 v17, 0x0

    cmp-long v15, v15, v17

    if-lez v15, :cond_6

    move v15, v4

    goto :goto_2

    :cond_6
    move v15, v9

    :goto_2
    iget-object v4, v6, Llyiahf/vczjk/zu1;->OooO0Oo:Ljava/lang/Object;

    check-cast v4, [Z

    aget-boolean v9, v4, v13

    if-eq v15, v9, :cond_8

    aput-boolean v15, v4, v13

    if-eqz v15, :cond_7

    sget-object v4, Llyiahf/vczjk/g86;->OooOOO:Llyiahf/vczjk/g86;

    :goto_3
    const/4 v14, 0x1

    goto :goto_4

    :catchall_0
    move-exception v0

    goto :goto_9

    :cond_7
    sget-object v4, Llyiahf/vczjk/g86;->OooOOOO:Llyiahf/vczjk/g86;

    goto :goto_3

    :cond_8
    sget-object v4, Llyiahf/vczjk/g86;->OooOOO0:Llyiahf/vczjk/g86;

    :goto_4
    aput-object v4, v12, v13
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    add-int/lit8 v13, v13, 0x1

    const/4 v4, 0x1

    const/4 v9, 0x0

    goto :goto_1

    :cond_9
    if-eqz v14, :cond_a

    goto :goto_5

    :cond_a
    move-object v12, v10

    :goto_5
    invoke-virtual {v8}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    :goto_6
    if-eqz v12, :cond_b

    sget-object v4, Llyiahf/vczjk/zx9;->OooOOO:Llyiahf/vczjk/zx9;

    new-instance v6, Llyiahf/vczjk/z0a;

    iget-object v7, v1, Llyiahf/vczjk/a1a;->this$0:Llyiahf/vczjk/b1a;

    invoke-direct {v6, v12, v7, v2, v10}, Llyiahf/vczjk/z0a;-><init>([Llyiahf/vczjk/g86;Llyiahf/vczjk/b1a;Llyiahf/vczjk/ay9;Llyiahf/vczjk/yo1;)V

    iput-object v10, v1, Llyiahf/vczjk/a1a;->L$0:Ljava/lang/Object;

    iput v5, v1, Llyiahf/vczjk/a1a;->label:I

    invoke-interface {v2, v4, v6, v1}, Llyiahf/vczjk/ay9;->OooO0O0(Llyiahf/vczjk/zx9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v0, :cond_b

    :goto_7
    return-object v0

    :cond_b
    :goto_8
    return-object v3

    :goto_9
    invoke-virtual {v8}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw v0
.end method
