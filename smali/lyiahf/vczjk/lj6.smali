.class public final Llyiahf/vczjk/lj6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/pj6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/pj6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/lj6;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/lj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/uo8;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lj6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lj6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lj6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/lj6;->label:I

    const/4 v2, 0x3

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v1, :cond_4

    if-eq v1, v5, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/lj6;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qj6;

    iget-object v2, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uo8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/uo8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v1

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/lj6;->L$3:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qj6;

    iget-object v2, p0, Llyiahf/vczjk/lj6;->L$1:Ljava/lang/Object;

    if-nez v2, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uo8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_0
    iget-object p1, v1, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/tj6;->OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v0, v3}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v3

    :catchall_0
    move-exception p1

    invoke-interface {v0, v3}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uo8;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v1, v1, Llyiahf/vczjk/pj6;->OooO0o:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v6, 0x0

    invoke-virtual {v1, v6, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    move-result v1

    if-eqz v1, :cond_7

    new-instance v1, Llyiahf/vczjk/fj6;

    iget-object v5, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-direct {v1, v5, p1, v3}, Llyiahf/vczjk/fj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/uo8;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    const/4 v1, 0x6

    invoke-static {v6, v1, v3}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v1

    new-instance v5, Llyiahf/vczjk/gj6;

    iget-object v6, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-direct {v5, v1, v3, v6}, Llyiahf/vczjk/gj6;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;Llyiahf/vczjk/pj6;)V

    invoke-static {p1, v3, v3, v5, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v5, Llyiahf/vczjk/kj6;

    iget-object v6, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-direct {v5, v1, v3, v6}, Llyiahf/vczjk/kj6;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;Llyiahf/vczjk/pj6;)V

    invoke-static {p1, v3, v3, v5, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    iput-object p1, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    iput-object v3, p0, Llyiahf/vczjk/lj6;->L$1:Ljava/lang/Object;

    iput-object v3, p0, Llyiahf/vczjk/lj6;->L$2:Ljava/lang/Object;

    iput-object v3, p0, Llyiahf/vczjk/lj6;->L$3:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/lj6;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/pj6;->OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_5

    goto :goto_1

    :cond_5
    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v1, v1, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v4, v1, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object p1, p0, Llyiahf/vczjk/lj6;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/lj6;->L$1:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/lj6;->L$2:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/lj6;->label:I

    invoke-virtual {v4, p0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v0, :cond_6

    :goto_1
    return-object v0

    :cond_6
    move-object v2, p1

    move-object v0, v4

    :goto_2
    :try_start_1
    iget-object p1, v1, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    sget-object v1, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    invoke-interface {v0, v3}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/lj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-static {p1, v2}, Llyiahf/vczjk/pj6;->OooO0Oo(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_1
    move-exception p1

    invoke-interface {v0, v3}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Attempt to collect twice from pageEventFlow, which is an illegal operation. Did you forget to call Flow<PagingData<*>>.cachedIn(coroutineScope)?"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
