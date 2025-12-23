.class public final Llyiahf/vczjk/et5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $priority:Llyiahf/vczjk/at5;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ht5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/at5;Llyiahf/vczjk/ht5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/et5;->$priority:Llyiahf/vczjk/at5;

    iput-object p2, p0, Llyiahf/vczjk/et5;->this$0:Llyiahf/vczjk/ht5;

    iput-object p3, p0, Llyiahf/vczjk/et5;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/et5;

    iget-object v1, p0, Llyiahf/vczjk/et5;->$priority:Llyiahf/vczjk/at5;

    iget-object v2, p0, Llyiahf/vczjk/et5;->this$0:Llyiahf/vczjk/ht5;

    iget-object v3, p0, Llyiahf/vczjk/et5;->$block:Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/et5;-><init>(Llyiahf/vczjk/at5;Llyiahf/vczjk/ht5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/et5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/et5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/et5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/et5;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/et5;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ht5;

    iget-object v1, p0, Llyiahf/vczjk/et5;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, p0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ct5;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_3

    :catchall_0
    move-exception p1

    goto/16 :goto_5

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/et5;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ht5;

    iget-object v3, p0, Llyiahf/vczjk/et5;->L$2:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/et5;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/jt5;

    iget-object v6, p0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ct5;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v1

    :goto_0
    move-object v1, v5

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/ct5;

    iget-object v5, p0, Llyiahf/vczjk/et5;->$priority:Llyiahf/vczjk/at5;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v6, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p1, v6}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast p1, Llyiahf/vczjk/v74;

    invoke-direct {v1, v5, p1}, Llyiahf/vczjk/ct5;-><init>(Llyiahf/vczjk/at5;Llyiahf/vczjk/v74;)V

    iget-object p1, p0, Llyiahf/vczjk/et5;->this$0:Llyiahf/vczjk/ht5;

    invoke-static {p1, v1}, Llyiahf/vczjk/ht5;->OooO00o(Llyiahf/vczjk/ht5;Llyiahf/vczjk/ct5;)V

    iget-object p1, p0, Llyiahf/vczjk/et5;->this$0:Llyiahf/vczjk/ht5;

    iget-object v5, p1, Llyiahf/vczjk/ht5;->OooO0O0:Llyiahf/vczjk/mt5;

    iget-object v6, p0, Llyiahf/vczjk/et5;->$block:Llyiahf/vczjk/oe3;

    iput-object v1, p0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/et5;->L$1:Ljava/lang/Object;

    iput-object v6, p0, Llyiahf/vczjk/et5;->L$2:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/et5;->L$3:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/et5;->label:I

    invoke-virtual {v5, p0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_3

    goto :goto_2

    :cond_3
    move-object v3, v6

    move-object v6, v1

    goto :goto_0

    :goto_1
    :try_start_1
    iput-object v6, p0, Llyiahf/vczjk/et5;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/et5;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/et5;->L$2:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/et5;->L$3:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/et5;->label:I

    invoke-interface {v3, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne v2, v0, :cond_4

    :goto_2
    return-object v0

    :cond_4
    move-object v0, p1

    move-object p1, v2

    move-object v2, v6

    :goto_3
    :try_start_2
    iget-object v0, v0, Llyiahf/vczjk/ht5;->OooO00o:Ljava/util/concurrent/atomic/AtomicReference;

    :cond_5
    invoke-virtual {v0, v2, v4}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_6

    goto :goto_4

    :cond_6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-eq v3, v2, :cond_5

    :goto_4
    invoke-interface {v1, v4}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object p1

    :catchall_1
    move-exception v0

    move-object v2, v0

    move-object v0, p1

    move-object p1, v2

    move-object v2, v6

    :goto_5
    :try_start_3
    iget-object v0, v0, Llyiahf/vczjk/ht5;->OooO00o:Ljava/util/concurrent/atomic/AtomicReference;

    :goto_6
    invoke-virtual {v0, v2, v4}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_7

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v2, :cond_7

    goto :goto_6

    :cond_7
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :catchall_2
    move-exception p1

    invoke-interface {v1, v4}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method
