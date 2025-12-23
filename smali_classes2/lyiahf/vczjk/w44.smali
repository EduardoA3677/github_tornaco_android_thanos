.class public final Llyiahf/vczjk/w44;
.super Llyiahf/vczjk/i88;
.source "SourceFile"


# static fields
.field public static final OooO:Llyiahf/vczjk/t44;

.field public static final OooO0OO:Llyiahf/vczjk/kz7;

.field public static final OooO0Oo:Llyiahf/vczjk/kz7;

.field public static final OooO0o:Ljava/util/concurrent/TimeUnit;

.field public static final OooO0o0:J

.field public static final OooO0oO:Llyiahf/vczjk/v44;

.field public static final OooO0oo:Z


# instance fields
.field public final OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    sput-object v0, Llyiahf/vczjk/w44;->OooO0o:Ljava/util/concurrent/TimeUnit;

    const-string v0, "rx2.io-keep-alive-time"

    const-wide/16 v1, 0x3c

    invoke-static {v0, v1, v2}, Ljava/lang/Long;->getLong(Ljava/lang/String;J)Ljava/lang/Long;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    sput-wide v0, Llyiahf/vczjk/w44;->OooO0o0:J

    new-instance v0, Llyiahf/vczjk/v44;

    new-instance v1, Llyiahf/vczjk/kz7;

    const-string v2, "RxCachedThreadSchedulerShutdown"

    invoke-direct {v1, v2}, Llyiahf/vczjk/kz7;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/v44;-><init>(Llyiahf/vczjk/kz7;)V

    sput-object v0, Llyiahf/vczjk/w44;->OooO0oO:Llyiahf/vczjk/v44;

    invoke-virtual {v0}, Llyiahf/vczjk/c16;->OooO00o()V

    const-string v0, "rx2.io-priority"

    const/4 v1, 0x5

    invoke-static {v0, v1}, Ljava/lang/Integer;->getInteger(Ljava/lang/String;I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    const/16 v1, 0xa

    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    const/4 v1, 0x1

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    new-instance v2, Llyiahf/vczjk/kz7;

    const-string v3, "RxCachedThreadScheduler"

    const/4 v4, 0x0

    invoke-direct {v2, v3, v0, v4}, Llyiahf/vczjk/kz7;-><init>(Ljava/lang/String;IZ)V

    sput-object v2, Llyiahf/vczjk/w44;->OooO0OO:Llyiahf/vczjk/kz7;

    new-instance v3, Llyiahf/vczjk/kz7;

    const-string v5, "RxCachedWorkerPoolEvictor"

    invoke-direct {v3, v5, v0, v4}, Llyiahf/vczjk/kz7;-><init>(Ljava/lang/String;IZ)V

    sput-object v3, Llyiahf/vczjk/w44;->OooO0Oo:Llyiahf/vczjk/kz7;

    const-string v0, "rx2.io-scheduled-release"

    invoke-static {v0}, Ljava/lang/Boolean;->getBoolean(Ljava/lang/String;)Z

    move-result v0

    sput-boolean v0, Llyiahf/vczjk/w44;->OooO0oo:Z

    new-instance v0, Llyiahf/vczjk/t44;

    const-wide/16 v3, 0x0

    const/4 v5, 0x0

    invoke-direct {v0, v3, v4, v5, v2}, Llyiahf/vczjk/t44;-><init>(JLjava/util/concurrent/TimeUnit;Llyiahf/vczjk/kz7;)V

    sput-object v0, Llyiahf/vczjk/w44;->OooO:Llyiahf/vczjk/t44;

    iget-object v2, v0, Llyiahf/vczjk/t44;->OooOOOO:Llyiahf/vczjk/cg1;

    invoke-virtual {v2}, Llyiahf/vczjk/cg1;->OooO00o()V

    iget-object v2, v0, Llyiahf/vczjk/t44;->OooOOo0:Ljava/util/concurrent/ScheduledFuture;

    if-eqz v2, :cond_0

    invoke-interface {v2, v1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/t44;->OooOOOo:Ljava/util/concurrent/ScheduledExecutorService;

    if-eqz v0, :cond_1

    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    :cond_1
    return-void
.end method

.method public constructor <init>()V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/w44;->OooO0OO:Llyiahf/vczjk/kz7;

    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    sget-object v2, Llyiahf/vczjk/w44;->OooO:Llyiahf/vczjk/t44;

    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/w44;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance v1, Llyiahf/vczjk/t44;

    sget-object v3, Llyiahf/vczjk/w44;->OooO0o:Ljava/util/concurrent/TimeUnit;

    sget-wide v4, Llyiahf/vczjk/w44;->OooO0o0:J

    invoke-direct {v1, v4, v5, v3, v0}, Llyiahf/vczjk/t44;-><init>(JLjava/util/concurrent/TimeUnit;Llyiahf/vczjk/kz7;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/w44;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0, v2, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eq v0, v2, :cond_0

    iget-object v0, v1, Llyiahf/vczjk/t44;->OooOOOO:Llyiahf/vczjk/cg1;

    invoke-virtual {v0}, Llyiahf/vczjk/cg1;->OooO00o()V

    iget-object v0, v1, Llyiahf/vczjk/t44;->OooOOo0:Ljava/util/concurrent/ScheduledFuture;

    if-eqz v0, :cond_2

    const/4 v2, 0x1

    invoke-interface {v0, v2}, Ljava/util/concurrent/Future;->cancel(Z)Z

    :cond_2
    iget-object v0, v1, Llyiahf/vczjk/t44;->OooOOOo:Ljava/util/concurrent/ScheduledExecutorService;

    if-eqz v0, :cond_3

    invoke-interface {v0}, Ljava/util/concurrent/ExecutorService;->shutdownNow()Ljava/util/List;

    :cond_3
    :goto_0
    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/h88;
    .locals 2

    new-instance v0, Llyiahf/vczjk/u44;

    iget-object v1, p0, Llyiahf/vczjk/w44;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t44;

    invoke-direct {v0, v1}, Llyiahf/vczjk/u44;-><init>(Llyiahf/vczjk/t44;)V

    return-object v0
.end method
