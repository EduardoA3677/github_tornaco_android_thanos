.class public final Llyiahf/vczjk/az4;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b52;


# static fields
.field public static final synthetic OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field public final synthetic OooOOOO:Llyiahf/vczjk/b52;

.field public final OooOOOo:Llyiahf/vczjk/qr1;

.field public final OooOOo:Llyiahf/vczjk/s45;

.field public final OooOOo0:I

.field public final OooOOoo:Ljava/lang/Object;

.field private volatile synthetic runningWorkers$volatile:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-class v0, Llyiahf/vczjk/az4;

    const-string v1, "runningWorkers$volatile"

    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qr1;I)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/qr1;-><init>()V

    instance-of v0, p1, Llyiahf/vczjk/b52;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/b52;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/c22;->OooO00o:Llyiahf/vczjk/b52;

    :cond_1
    iput-object v0, p0, Llyiahf/vczjk/az4;->OooOOOO:Llyiahf/vczjk/b52;

    iput-object p1, p0, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    iput p2, p0, Llyiahf/vczjk/az4;->OooOOo0:I

    new-instance p1, Llyiahf/vczjk/s45;

    invoke-direct {p1}, Llyiahf/vczjk/s45;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/az4;->OooOOo:Llyiahf/vczjk/s45;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/az4;->OooOOoo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OoooOO0(JLlyiahf/vczjk/yp0;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/az4;->OooOOOO:Llyiahf/vczjk/b52;

    invoke-interface {v0, p1, p2, p3}, Llyiahf/vczjk/b52;->OoooOO0(JLlyiahf/vczjk/yp0;)V

    return-void
.end method

.method public final o0000()Ljava/lang/Runnable;
    .locals 3

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/az4;->OooOOo:Llyiahf/vczjk/s45;

    invoke-virtual {v0}, Llyiahf/vczjk/s45;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Runnable;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/az4;->OooOOoo:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I

    iget-object v2, p0, Llyiahf/vczjk/az4;->OooOOo:Llyiahf/vczjk/s45;

    invoke-virtual {v2}, Llyiahf/vczjk/s45;->OooO0OO()I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v2, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1

    :cond_1
    return-object v0
.end method

.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/az4;->OooOOo:Llyiahf/vczjk/s45;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s45;->OooO00o(Ljava/lang/Runnable;)Z

    sget-object p1, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p2

    iget v0, p0, Llyiahf/vczjk/az4;->OooOOo0:I

    if-ge p2, v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/az4;->o0000O00()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/az4;->o0000()Ljava/lang/Runnable;

    move-result-object p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    new-instance v0, Llyiahf/vczjk/js2;

    const/16 v1, 0xa

    invoke-direct {v0, v1, p0, p2}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-static {p2, p0, v0}, Llyiahf/vczjk/dn8;->o0ooOO0(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p2

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I

    throw p2

    :cond_1
    :goto_0
    return-void
.end method

.method public final o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 1

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOoOO(I)V

    iget v0, p0, Llyiahf/vczjk/az4;->OooOOo0:I

    if-lt p1, v0, :cond_0

    return-object p0

    :cond_0
    invoke-super {p0, p1}, Llyiahf/vczjk/qr1;->o00000oo(I)Llyiahf/vczjk/qr1;

    move-result-object p1

    return-object p1
.end method

.method public final o0000O00()Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/az4;->OooOOoo:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result v2

    iget v3, p0, Llyiahf/vczjk/az4;->OooOOo0:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lt v2, v3, :cond_0

    monitor-exit v0

    const/4 v0, 0x0

    return v0

    :cond_0
    :try_start_1
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->incrementAndGet(Ljava/lang/Object;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    const/4 v0, 0x1

    return v0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method public final o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/az4;->OooOOo:Llyiahf/vczjk/s45;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s45;->OooO00o(Ljava/lang/Runnable;)Z

    sget-object p1, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p2

    iget v0, p0, Llyiahf/vczjk/az4;->OooOOo0:I

    if-ge p2, v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/az4;->o0000O00()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/az4;->o0000()Ljava/lang/Runnable;

    move-result-object p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    new-instance v0, Llyiahf/vczjk/js2;

    const/16 v1, 0xa

    invoke-direct {v0, v1, p0, p2}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-virtual {p2, p0, v0}, Llyiahf/vczjk/qr1;->o0000Ooo(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p2

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I

    throw p2

    :cond_1
    :goto_0
    return-void
.end method

.method public final o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/az4;->OooOOOO:Llyiahf/vczjk/b52;

    invoke-interface {v0, p1, p2, p3, p4}, Llyiahf/vczjk/b52;->o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ".limitedParallelism("

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/az4;->OooOOo0:I

    const/16 v2, 0x29

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ix8;->OooO(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
