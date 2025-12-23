.class public final Llyiahf/vczjk/ms2;
.super Llyiahf/vczjk/h88;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/era;

.field public final OooOOO0:Ljava/util/concurrent/ExecutorService;

.field public volatile OooOOOO:Z

.field public final OooOOOo:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final OooOOo0:Llyiahf/vczjk/cg1;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ms2;->OooOOOo:Ljava/util/concurrent/atomic/AtomicInteger;

    new-instance v0, Llyiahf/vczjk/cg1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/cg1;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/ms2;->OooOOo0:Llyiahf/vczjk/cg1;

    iput-object p1, p0, Llyiahf/vczjk/ms2;->OooOOO0:Ljava/util/concurrent/ExecutorService;

    new-instance p1, Llyiahf/vczjk/era;

    const/16 v0, 0x15

    invoke-direct {p1, v0}, Llyiahf/vczjk/era;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/ms2;->OooOOO:Llyiahf/vczjk/era;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/ms2;->OooOOo0:Llyiahf/vczjk/cg1;

    invoke-virtual {v0}, Llyiahf/vczjk/cg1;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/ms2;->OooOOOo:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ms2;->OooOOO:Llyiahf/vczjk/era;

    invoke-virtual {v0}, Llyiahf/vczjk/era;->clear()V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    sget-object v1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    if-eqz v0, :cond_0

    return-object v1

    :cond_0
    new-instance v0, Llyiahf/vczjk/ls2;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ls2;-><init>(Ljava/lang/Runnable;)V

    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOO:Llyiahf/vczjk/era;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/era;->OooO0o0(Ljava/lang/Object;)Z

    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOOo:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    move-result p1

    if-nez p1, :cond_1

    :try_start_0
    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOO0:Ljava/util/concurrent/ExecutorService;

    invoke-interface {p1, p0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/ms2;->OooOOO:Llyiahf/vczjk/era;

    invoke-virtual {v0}, Llyiahf/vczjk/era;->clear()V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-object v1

    :cond_1
    return-object v0
.end method

.method public final OooO0Oo(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
    .locals 5

    const-wide/16 v0, 0x0

    cmp-long v0, p2, v0

    if-gtz v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ms2;->OooO0OO(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    return-object p1

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    sget-object v1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    if-eqz v0, :cond_1

    return-object v1

    :cond_1
    new-instance v0, Llyiahf/vczjk/eg8;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    new-instance v2, Llyiahf/vczjk/eg8;

    invoke-direct {v2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/f88;

    new-instance v4, Llyiahf/vczjk/uj1;

    invoke-direct {v4, p0, v2, p1}, Llyiahf/vczjk/uj1;-><init>(Llyiahf/vczjk/ms2;Llyiahf/vczjk/eg8;Ljava/lang/Runnable;)V

    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOo0:Llyiahf/vczjk/cg1;

    invoke-direct {v3, v4, p1}, Llyiahf/vczjk/f88;-><init>(Ljava/lang/Runnable;Llyiahf/vczjk/cg1;)V

    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOo0:Llyiahf/vczjk/cg1;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    iget-object p1, p0, Llyiahf/vczjk/ms2;->OooOOO0:Ljava/util/concurrent/ExecutorService;

    instance-of v4, p1, Ljava/util/concurrent/ScheduledExecutorService;

    if-eqz v4, :cond_2

    :try_start_0
    check-cast p1, Ljava/util/concurrent/ScheduledExecutorService;

    invoke-interface {p1, v3, p2, p3, p4}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object p1

    invoke-virtual {v3, p1}, Llyiahf/vczjk/f88;->OooO0O0(Ljava/util/concurrent/Future;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-object v1

    :cond_2
    sget-object p1, Llyiahf/vczjk/ns2;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v3, p2, p3, p4}, Llyiahf/vczjk/i88;->OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/xc2;

    invoke-direct {p2, p1}, Llyiahf/vczjk/xc2;-><init>(Llyiahf/vczjk/nc2;)V

    invoke-virtual {v3, p2}, Llyiahf/vczjk/f88;->OooO0O0(Ljava/util/concurrent/Future;)V

    :goto_0
    invoke-static {v0, v3}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-object v2
.end method

.method public final run()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ms2;->OooOOO:Llyiahf/vczjk/era;

    const/4 v1, 0x1

    :cond_0
    iget-boolean v2, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    if-eqz v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/era;->clear()V

    return-void

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/era;->OooOOo0()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Runnable;

    if-nez v2, :cond_3

    iget-boolean v2, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    if-eqz v2, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/era;->clear()V

    return-void

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/ms2;->OooOOOo:Ljava/util/concurrent/atomic/AtomicInteger;

    neg-int v1, v1

    invoke-virtual {v2, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    move-result v1

    if-nez v1, :cond_0

    return-void

    :cond_3
    invoke-interface {v2}, Ljava/lang/Runnable;->run()V

    iget-boolean v2, p0, Llyiahf/vczjk/ms2;->OooOOOO:Z

    if-eqz v2, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/era;->clear()V

    return-void
.end method
