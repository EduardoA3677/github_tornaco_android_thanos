.class public final Llyiahf/vczjk/ml2;
.super Llyiahf/vczjk/ng0;
.source "SourceFile"


# instance fields
.field public final synthetic OooOO0o:Llyiahf/vczjk/nl2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nl2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ml2;->OooOO0o:Llyiahf/vczjk/nl2;

    return-void
.end method


# virtual methods
.method public final OoooO0(Llyiahf/vczjk/ld9;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ml2;->OooOO0o:Llyiahf/vczjk/nl2;

    iput-object p1, v0, Llyiahf/vczjk/nl2;->OooO0OO:Llyiahf/vczjk/ld9;

    new-instance p1, Llyiahf/vczjk/uqa;

    iget-object v1, v0, Llyiahf/vczjk/nl2;->OooO0OO:Llyiahf/vczjk/ld9;

    iget-object v2, v0, Llyiahf/vczjk/nl2;->OooO00o:Llyiahf/vczjk/rl2;

    iget-object v3, v2, Llyiahf/vczjk/rl2;->OooO0oO:Llyiahf/vczjk/uk2;

    iget-object v2, v2, Llyiahf/vczjk/rl2;->OooO:Llyiahf/vczjk/h22;

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x22

    if-lt v4, v5, :cond_0

    invoke-static {}, Llyiahf/vczjk/xl2;->OooO00o()Ljava/util/Set;

    move-result-object v4

    goto :goto_0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/tg0;->OooOoo()Ljava/util/Set;

    move-result-object v4

    :goto_0
    invoke-direct {p1, v1, v3, v2, v4}, Llyiahf/vczjk/uqa;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/uk2;Llyiahf/vczjk/h22;Ljava/util/Set;)V

    iput-object p1, v0, Llyiahf/vczjk/nl2;->OooO0O0:Llyiahf/vczjk/uqa;

    iget-object p1, v0, Llyiahf/vczjk/nl2;->OooO00o:Llyiahf/vczjk/rl2;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v1, p1, Llyiahf/vczjk/rl2;->OooO00o:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    const/4 v1, 0x1

    :try_start_0
    iput v1, p1, Llyiahf/vczjk/rl2;->OooO0OO:I

    iget-object v1, p1, Llyiahf/vczjk/rl2;->OooO0O0:Llyiahf/vczjk/ny;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    iget-object v1, p1, Llyiahf/vczjk/rl2;->OooO0O0:Llyiahf/vczjk/ny;

    invoke-virtual {v1}, Llyiahf/vczjk/ny;->clear()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v1, p1, Llyiahf/vczjk/rl2;->OooO00o:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    iget-object v1, p1, Llyiahf/vczjk/rl2;->OooO0Oo:Landroid/os/Handler;

    new-instance v2, Llyiahf/vczjk/ro0;

    iget p1, p1, Llyiahf/vczjk/rl2;->OooO0OO:I

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/ro0;-><init>(Ljava/util/List;ILjava/lang/Throwable;)V

    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void

    :catchall_0
    move-exception v0

    iget-object p1, p1, Llyiahf/vczjk/rl2;->OooO00o:Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    invoke-virtual {p1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/Lock;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw v0
.end method

.method public final OoooO00(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ml2;->OooOO0o:Llyiahf/vczjk/nl2;

    iget-object v0, v0, Llyiahf/vczjk/nl2;->OooO00o:Llyiahf/vczjk/rl2;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rl2;->OooO0o(Ljava/lang/Throwable;)V

    return-void
.end method
