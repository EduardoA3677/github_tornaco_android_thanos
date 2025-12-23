.class public final Llyiahf/vczjk/is2;
.super Llyiahf/vczjk/hs2;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b52;


# instance fields
.field public final OooOOOO:Ljava/util/concurrent/Executor;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/Executor;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/qr1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    sget-object v0, Llyiahf/vczjk/oh1;->OooO00o:Ljava/lang/reflect/Method;

    :try_start_0
    instance-of v0, p1, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    if-eqz v0, :cond_0

    check-cast p1, Ljava/util/concurrent/ScheduledThreadPoolExecutor;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    sget-object v0, Llyiahf/vczjk/oh1;->OooO00o:Ljava/lang/reflect/Method;

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    :goto_1
    return-void
.end method


# virtual methods
.method public final OoooOO0(JLlyiahf/vczjk/yp0;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    instance-of v1, v0, Ljava/util/concurrent/ScheduledExecutorService;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Ljava/util/concurrent/ScheduledExecutorService;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_1

    new-instance v1, Llyiahf/vczjk/js2;

    const/16 v3, 0xf

    const/4 v4, 0x0

    invoke-direct {v1, v3, p0, p3, v4}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    :try_start_0
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-interface {v0, v1, p1, p2, v3}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object v2
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v0

    new-instance v1, Ljava/util/concurrent/CancellationException;

    const-string v3, "The task was rejected"

    invoke-direct {v1, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    iget-object v0, p3, Llyiahf/vczjk/yp0;->OooOOo0:Llyiahf/vczjk/or1;

    invoke-static {v0, v1}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    :cond_1
    :goto_1
    if-eqz v2, :cond_2

    new-instance p1, Llyiahf/vczjk/mp0;

    const/4 p2, 0x0

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/mp0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/yp0;->OooOo0O(Llyiahf/vczjk/o26;)V

    return-void

    :cond_2
    sget-object v0, Llyiahf/vczjk/b22;->OooOo0O:Llyiahf/vczjk/b22;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/or2;->OoooOO0(JLlyiahf/vczjk/yp0;)V

    return-void
.end method

.method public final close()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    instance-of v1, v0, Ljava/util/concurrent/ExecutorService;

    if-eqz v1, :cond_0

    check-cast v0, Ljava/util/concurrent/ExecutorService;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    :cond_1
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/is2;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/is2;

    iget-object p1, p1, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

.method public final o0000()Ljava/util/concurrent/Executor;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    return-object v0
.end method

.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 3

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    invoke-interface {v0, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    new-instance v1, Ljava/util/concurrent/CancellationException;

    const-string v2, "The task was rejected"

    invoke-direct {v1, v2}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    invoke-static {p1, v1}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/m22;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    instance-of v1, v0, Ljava/util/concurrent/ScheduledExecutorService;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Ljava/util/concurrent/ScheduledExecutorService;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_1

    :try_start_0
    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-interface {v0, p3, p1, p2, v1}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object v2
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v0

    new-instance v1, Ljava/util/concurrent/CancellationException;

    const-string v3, "The task was rejected"

    invoke-direct {v1, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    invoke-static {p4, v1}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    :cond_1
    :goto_1
    if-eqz v2, :cond_2

    new-instance p1, Llyiahf/vczjk/rc2;

    invoke-direct {p1, v2}, Llyiahf/vczjk/rc2;-><init>(Ljava/util/concurrent/ScheduledFuture;)V

    return-object p1

    :cond_2
    sget-object v0, Llyiahf/vczjk/b22;->OooOo0O:Llyiahf/vczjk/b22;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/b22;->o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/is2;->OooOOOO:Ljava/util/concurrent/Executor;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
