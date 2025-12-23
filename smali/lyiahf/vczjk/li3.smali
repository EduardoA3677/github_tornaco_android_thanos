.class public final Llyiahf/vczjk/li3;
.super Llyiahf/vczjk/ps5;
.source "SourceFile"


# virtual methods
.method public final OooO0OO()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/nv8;->OooOOOO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method public final OooOO0O()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOO0o()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOO0()V
    .locals 0

    invoke-static {}, Llyiahf/vczjk/vv8;->OooO00o()V

    return-void
.end method

.method public final OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ki3;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ki3;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance p1, Llyiahf/vczjk/uv8;

    invoke-direct {p1, v0}, Llyiahf/vczjk/uv8;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-static {p1}, Llyiahf/vczjk/vv8;->OooO0o(Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nv8;

    check-cast p1, Llyiahf/vczjk/fh7;

    return-object p1
.end method

.method public final OooOo0o()Llyiahf/vczjk/xr6;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot apply the global snapshot directly. Call Snapshot.advanceGlobalSnapshot"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooOoo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ps5;
    .locals 1

    new-instance v0, Llyiahf/vczjk/ji3;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ji3;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance p1, Llyiahf/vczjk/uv8;

    invoke-direct {p1, v0}, Llyiahf/vczjk/uv8;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-static {p1}, Llyiahf/vczjk/vv8;->OooO0o(Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nv8;

    check-cast p1, Llyiahf/vczjk/ps5;

    return-object p1
.end method
