.class public final Llyiahf/vczjk/ns2;
.super Llyiahf/vczjk/i88;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/i88;


# instance fields
.field public final OooO0O0:Ljava/util/concurrent/ExecutorService;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    sput-object v0, Llyiahf/vczjk/ns2;->OooO0OO:Llyiahf/vczjk/i88;

    return-void
.end method

.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ns2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/h88;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ms2;

    iget-object v1, p0, Llyiahf/vczjk/ns2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ms2;-><init>(Ljava/util/concurrent/ExecutorService;)V

    return-object v0
.end method

.method public final OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ns2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    if-eqz v0, :cond_0

    :try_start_0
    new-instance v1, Llyiahf/vczjk/e88;

    invoke-direct {v1, p1}, Llyiahf/vczjk/o000O00;-><init>(Ljava/lang/Runnable;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    move-result-object p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o000O00;->OooO0O0(Ljava/util/concurrent/Future;)V

    return-object v1

    :catch_0
    move-exception p1

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/ls2;

    invoke-direct {v1, p1}, Llyiahf/vczjk/ls2;-><init>(Ljava/lang/Runnable;)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1
.end method

.method public final OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ns2;->OooO0O0:Ljava/util/concurrent/ExecutorService;

    instance-of v1, v0, Ljava/util/concurrent/ScheduledExecutorService;

    if-eqz v1, :cond_0

    :try_start_0
    new-instance v1, Llyiahf/vczjk/e88;

    invoke-direct {v1, p1}, Llyiahf/vczjk/o000O00;-><init>(Ljava/lang/Runnable;)V

    check-cast v0, Ljava/util/concurrent/ScheduledExecutorService;

    invoke-interface {v0, v1, p2, p3, p4}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/util/concurrent/Callable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    move-result-object p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o000O00;->OooO0O0(Ljava/util/concurrent/Future;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    sget-object p1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/ks2;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ks2;-><init>(Ljava/lang/Runnable;)V

    new-instance p1, Llyiahf/vczjk/js2;

    const/4 v1, 0x0

    invoke-direct {p1, v1, p0, v0}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/ns2;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v1, p1, p2, p3, p4}, Llyiahf/vczjk/i88;->OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;

    move-result-object p1

    iget-object p2, v0, Llyiahf/vczjk/ks2;->timed:Llyiahf/vczjk/eg8;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p2, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-object v0
.end method
