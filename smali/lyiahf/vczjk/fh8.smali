.class public final Llyiahf/vczjk/fh8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $arg0:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Llyiahf/vczjk/eh8;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $session:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $sessionInitializer:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fh8;->$sessionInitializer:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/fh8;->$arg0:Ljava/util/concurrent/atomic/AtomicReference;

    iput-object p3, p0, Llyiahf/vczjk/fh8;->$session:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/fh8;

    iget-object v1, p0, Llyiahf/vczjk/fh8;->$sessionInitializer:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/fh8;->$arg0:Ljava/util/concurrent/atomic/AtomicReference;

    iget-object v3, p0, Llyiahf/vczjk/fh8;->$session:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/fh8;-><init>(Llyiahf/vczjk/oe3;Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fh8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fh8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fh8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/fh8;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/eh8;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception p1

    goto/16 :goto_5

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eh8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/eh8;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/zsa;->OoooOOo(Llyiahf/vczjk/or1;)Llyiahf/vczjk/v74;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/fh8;->$sessionInitializer:Llyiahf/vczjk/oe3;

    invoke-interface {v6, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v1, v5, p1}, Llyiahf/vczjk/eh8;-><init>(Llyiahf/vczjk/v74;Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fh8;->$arg0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/eh8;

    if-eqz p1, :cond_4

    iget-object p1, p1, Llyiahf/vczjk/eh8;->OooO00o:Llyiahf/vczjk/v74;

    iput-object v1, p0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/fh8;->label:I

    invoke-interface {p1, v2}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    invoke-interface {p1, p0}, Llyiahf/vczjk/v74;->Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    if-ne p1, v0, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/fh8;->$session:Llyiahf/vczjk/ze3;

    iget-object v4, v1, Llyiahf/vczjk/eh8;->OooO0O0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/fh8;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/fh8;->label:I

    invoke-interface {p1, v4, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne p1, v0, :cond_5

    :goto_2
    return-object v0

    :cond_5
    move-object v0, v1

    :goto_3
    iget-object v3, p0, Llyiahf/vczjk/fh8;->$arg0:Ljava/util/concurrent/atomic/AtomicReference;

    :cond_6
    invoke-virtual {v3, v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    goto :goto_4

    :cond_7
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    if-eq v1, v0, :cond_6

    :goto_4
    return-object p1

    :catchall_1
    move-exception p1

    move-object v0, v1

    :goto_5
    iget-object v1, p0, Llyiahf/vczjk/fh8;->$arg0:Ljava/util/concurrent/atomic/AtomicReference;

    :goto_6
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_8

    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_8

    goto :goto_6

    :cond_8
    throw p1
.end method
