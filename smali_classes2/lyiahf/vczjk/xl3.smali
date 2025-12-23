.class public final Llyiahf/vczjk/xl3;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b52;


# instance fields
.field public final OooOOOO:Landroid/os/Handler;

.field public final OooOOOo:Ljava/lang/String;

.field public final OooOOo:Llyiahf/vczjk/xl3;

.field public final OooOOo0:Z


# direct methods
.method public constructor <init>(Landroid/os/Handler;)V
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x0

    invoke-direct {p0, p1, v1, v0}, Llyiahf/vczjk/xl3;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    return-void
.end method

.method public constructor <init>(Landroid/os/Handler;Ljava/lang/String;Z)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/qr1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    iput-object p2, p0, Llyiahf/vczjk/xl3;->OooOOOo:Ljava/lang/String;

    iput-boolean p3, p0, Llyiahf/vczjk/xl3;->OooOOo0:Z

    if-eqz p3, :cond_0

    move-object p3, p0

    goto :goto_0

    :cond_0
    new-instance p3, Llyiahf/vczjk/xl3;

    const/4 v0, 0x1

    invoke-direct {p3, p1, p2, v0}, Llyiahf/vczjk/xl3;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    :goto_0
    iput-object p3, p0, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    return-void
.end method


# virtual methods
.method public final OoooOO0(JLlyiahf/vczjk/yp0;)V
    .locals 4

    new-instance v0, Llyiahf/vczjk/oO0oO000;

    const/16 v1, 0x1d

    invoke-direct {v0, v1, p3, p0}, Llyiahf/vczjk/oO0oO000;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const-wide v1, 0x3fffffffffffffffL    # 1.9999999999999998

    cmp-long v3, p1, v1

    if-lez v3, :cond_0

    move-wide p1, v1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-virtual {v1, v0, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    move-result p1

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/o0OO000o;

    const/16 p2, 0x10

    invoke-direct {p1, p2, p0, v0}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    return-void

    :cond_1
    iget-object p1, p3, Llyiahf/vczjk/yp0;->OooOOo0:Llyiahf/vczjk/or1;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/xl3;->o0000(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/xl3;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/xl3;

    iget-object v0, p1, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    iget-object v1, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    if-ne v0, v1, :cond_0

    iget-boolean p1, p1, Llyiahf/vczjk/xl3;->OooOOo0:Z

    iget-boolean v0, p0, Llyiahf/vczjk/xl3;->OooOOo0:Z

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-static {v0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v0

    iget-boolean v1, p0, Llyiahf/vczjk/xl3;->OooOOo0:Z

    if-eqz v1, :cond_0

    const/16 v1, 0x4cf

    goto :goto_0

    :cond_0
    const/16 v1, 0x4d5

    :goto_0
    xor-int/2addr v0, v1

    return v0
.end method

.method public final o0000(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 3

    new-instance v0, Ljava/util/concurrent/CancellationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "The task was rejected, the handler underlying the dispatcher \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, "\' was closed"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/m22;->o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    return-void
.end method

.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-virtual {v0, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xl3;->o0000(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public final o00000oO(Llyiahf/vczjk/or1;)Z
    .locals 1

    iget-boolean p1, p0, Llyiahf/vczjk/xl3;->OooOOo0:Z

    if-eqz p1, :cond_1

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 0

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOoOO(I)V

    return-object p0
.end method

.method public final o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;
    .locals 3

    const-wide v0, 0x3fffffffffffffffL    # 1.9999999999999998

    cmp-long v2, p1, v0

    if-lez v2, :cond_0

    move-wide p1, v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-virtual {v0, p3, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    move-result p1

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/wl3;

    invoke-direct {p1, p0, p3}, Llyiahf/vczjk/wl3;-><init>(Llyiahf/vczjk/xl3;Ljava/lang/Runnable;)V

    return-object p1

    :cond_1
    invoke-virtual {p0, p4, p3}, Llyiahf/vczjk/xl3;->o0000(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V

    sget-object p1, Llyiahf/vczjk/i26;->OooOOO0:Llyiahf/vczjk/i26;

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    if-ne p0, v0, :cond_0

    const-string v0, "Dispatchers.Main"

    goto :goto_1

    :cond_0
    const/4 v1, 0x0

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-object v0, v1

    :goto_0
    if-ne p0, v0, :cond_1

    const-string v0, "Dispatchers.Main.immediate"

    goto :goto_1

    :cond_1
    move-object v0, v1

    :goto_1
    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOo:Ljava/lang/String;

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/xl3;->OooOOOO:Landroid/os/Handler;

    invoke-virtual {v0}, Landroid/os/Handler;->toString()Ljava/lang/String;

    move-result-object v0

    :cond_2
    iget-boolean v1, p0, Llyiahf/vczjk/xl3;->OooOOo0:Z

    if-eqz v1, :cond_3

    const-string v1, ".immediate"

    invoke-static {v0, v1}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :cond_3
    return-object v0
.end method
