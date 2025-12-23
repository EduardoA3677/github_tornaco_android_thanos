.class public final Llyiahf/vczjk/w00;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# static fields
.field public static OooOo0:Llyiahf/vczjk/nq2;

.field public static final OooOo00:Ljava/util/concurrent/ThreadPoolExecutor;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/e95;

.field public final OooOOO0:Llyiahf/vczjk/bl5;

.field public volatile OooOOOO:I

.field public final OooOOOo:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final OooOOo:Ljava/util/concurrent/CountDownLatch;

.field public final OooOOo0:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final synthetic OooOOoo:Llyiahf/vczjk/vy2;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    new-instance v7, Llyiahf/vczjk/l42;

    const/4 v0, 0x1

    invoke-direct {v7, v0}, Llyiahf/vczjk/l42;-><init>(I)V

    new-instance v6, Ljava/util/concurrent/LinkedBlockingQueue;

    const/16 v0, 0xa

    invoke-direct {v6, v0}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>(I)V

    new-instance v0, Ljava/util/concurrent/ThreadPoolExecutor;

    sget-object v5, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    const/4 v1, 0x5

    const/16 v2, 0x80

    const-wide/16 v3, 0x1

    invoke-direct/range {v0 .. v7}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    sput-object v0, Llyiahf/vczjk/w00;->OooOo00:Ljava/util/concurrent/ThreadPoolExecutor;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/vy2;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w00;->OooOOoo:Llyiahf/vczjk/vy2;

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/w00;->OooOOOO:I

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/w00;->OooOOOo:Ljava/util/concurrent/atomic/AtomicBoolean;

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/w00;->OooOOo0:Ljava/util/concurrent/atomic/AtomicBoolean;

    new-instance v0, Llyiahf/vczjk/bl5;

    invoke-direct {v0, p0}, Llyiahf/vczjk/bl5;-><init>(Llyiahf/vczjk/w00;)V

    iput-object v0, p0, Llyiahf/vczjk/w00;->OooOOO0:Llyiahf/vczjk/bl5;

    new-instance v1, Llyiahf/vczjk/e95;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/e95;-><init>(Llyiahf/vczjk/w00;Llyiahf/vczjk/bl5;)V

    iput-object v1, p0, Llyiahf/vczjk/w00;->OooOOO:Llyiahf/vczjk/e95;

    new-instance v0, Ljava/util/concurrent/CountDownLatch;

    invoke-direct {v0, p1}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/w00;->OooOOo:Ljava/util/concurrent/CountDownLatch;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)V
    .locals 4

    const-class v0, Llyiahf/vczjk/w00;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/w00;->OooOo0:Llyiahf/vczjk/nq2;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/nq2;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/nq2;-><init>(Landroid/os/Looper;I)V

    sput-object v1, Llyiahf/vczjk/w00;->OooOo0:Llyiahf/vczjk/nq2;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    sget-object v1, Llyiahf/vczjk/w00;->OooOo0:Llyiahf/vczjk/nq2;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    new-instance v0, Llyiahf/vczjk/cl5;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/cl5;-><init>(Llyiahf/vczjk/w00;[Ljava/lang/Object;)V

    const/4 p1, 0x1

    invoke-virtual {v1, p1, v0}, Landroid/os/Handler;->obtainMessage(ILjava/lang/Object;)Landroid/os/Message;

    move-result-object p1

    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    return-void

    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public final run()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w00;->OooOOoo:Llyiahf/vczjk/vy2;

    invoke-virtual {v0}, Llyiahf/vczjk/vy2;->OooO0O0()V

    return-void
.end method
