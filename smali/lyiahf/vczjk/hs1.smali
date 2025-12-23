.class public final Llyiahf/vczjk/hs1;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Lcom/absinthe/rulesbundle/RuleDatabase_Impl;Landroid/os/CancellationSignal;Ljava/util/concurrent/Callable;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p4, Llyiahf/vczjk/fs1;

    if-eqz v0, :cond_0

    move-object v0, p4

    check-cast v0, Llyiahf/vczjk/fs1;

    iget v1, v0, Llyiahf/vczjk/fs1;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/fs1;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/fs1;

    invoke-direct {v0, p0, p4}, Llyiahf/vczjk/fs1;-><init>(Llyiahf/vczjk/hs1;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p4, v0, Llyiahf/vczjk/fs1;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/fs1;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$3:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/or1;

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$2:Ljava/lang/Object;

    check-cast p1, Ljava/util/concurrent/Callable;

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$1:Ljava/lang/Object;

    check-cast p1, Landroid/os/CancellationSignal;

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ru7;

    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$2:Ljava/lang/Object;

    move-object p3, p1

    check-cast p3, Ljava/util/concurrent/Callable;

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$1:Ljava/lang/Object;

    move-object p2, p1

    check-cast p2, Landroid/os/CancellationSignal;

    iget-object p1, v0, Llyiahf/vczjk/fs1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ru7;

    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->isOpenInternal()Z

    move-result p4

    if-eqz p4, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->inTransaction()Z

    move-result p4

    if-eqz p4, :cond_4

    invoke-interface {p3}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_4
    iput-object p1, v0, Llyiahf/vczjk/fs1;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/fs1;->L$1:Ljava/lang/Object;

    iput-object p3, v0, Llyiahf/vczjk/fs1;->L$2:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/fs1;->label:I

    invoke-static {p1, v0}, Llyiahf/vczjk/u34;->OooOo0o(Llyiahf/vczjk/ru7;Llyiahf/vczjk/zo1;)Llyiahf/vczjk/or1;

    move-result-object p4

    if-ne p4, v1, :cond_5

    goto :goto_2

    :cond_5
    :goto_1
    check-cast p4, Llyiahf/vczjk/or1;

    iput-object p1, v0, Llyiahf/vczjk/fs1;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/fs1;->L$1:Ljava/lang/Object;

    iput-object p3, v0, Llyiahf/vczjk/fs1;->L$2:Ljava/lang/Object;

    iput-object p4, v0, Llyiahf/vczjk/fs1;->L$3:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/fs1;->label:I

    new-instance v2, Llyiahf/vczjk/yp0;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    invoke-direct {v2, v4, v0}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOoo()V

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->getCoroutineScope()Llyiahf/vczjk/xr1;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/gs1;

    const/4 v4, 0x0

    invoke-direct {v0, p3, v2, v4}, Llyiahf/vczjk/gs1;-><init>(Ljava/util/concurrent/Callable;Llyiahf/vczjk/wp0;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, p4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/o0oOO;

    const/4 p4, 0x4

    invoke-direct {p3, p4, p2, p1}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2, p3}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_6

    :goto_2
    return-object v1

    :cond_6
    return-object p1
.end method
