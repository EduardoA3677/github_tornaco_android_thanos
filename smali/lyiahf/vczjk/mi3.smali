.class public final Llyiahf/vczjk/mi3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $channel:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mi3;->$channel:Llyiahf/vczjk/rs0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/mi3;

    iget-object v0, p0, Llyiahf/vczjk/mi3;->$channel:Llyiahf/vczjk/rs0;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/mi3;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mi3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mi3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mi3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mi3;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/mi3;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v4, p0, Llyiahf/vczjk/mi3;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ui7;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v4, p0, Llyiahf/vczjk/mi3;->$channel:Llyiahf/vczjk/rs0;

    :try_start_1
    invoke-interface {v4}, Llyiahf/vczjk/ui7;->iterator()Llyiahf/vczjk/ej0;

    move-result-object p1

    move-object v1, p1

    :cond_2
    :goto_0
    iput-object v4, p0, Llyiahf/vczjk/mi3;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/mi3;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/mi3;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z8a;

    sget-object p1, Llyiahf/vczjk/oi3;->OooO0O0:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v5, 0x0

    invoke-virtual {p1, v5}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    sget-object p1, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    sget-object v6, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object v6, v6, Llyiahf/vczjk/ps5;->OooO0oo:Llyiahf/vczjk/ks5;

    if-eqz v6, :cond_4

    invoke-virtual {v6}, Llyiahf/vczjk/a88;->OooO0OO()Z

    move-result v6
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    if-ne v6, v3, :cond_4

    move v5, v3

    goto :goto_2

    :catchall_1
    move-exception v0

    goto :goto_3

    :cond_4
    :goto_2
    :try_start_3
    monitor-exit p1

    if-eqz v5, :cond_2

    invoke-static {}, Llyiahf/vczjk/vv8;->OooO00o()V

    goto :goto_0

    :goto_3
    monitor-exit p1

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :cond_5
    invoke-interface {v4, v2}, Llyiahf/vczjk/ui7;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_4
    :try_start_4
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception v0

    instance-of v1, p1, Ljava/util/concurrent/CancellationException;

    if-eqz v1, :cond_6

    move-object v2, p1

    check-cast v2, Ljava/util/concurrent/CancellationException;

    :cond_6
    if-nez v2, :cond_7

    new-instance v2, Ljava/util/concurrent/CancellationException;

    const-string v1, "Channel was consumed, consumer had failed"

    invoke-direct {v2, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    :cond_7
    invoke-interface {v4, v2}, Llyiahf/vczjk/ui7;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    throw v0
.end method
