.class public final Llyiahf/vczjk/aj5;
.super Llyiahf/vczjk/dg5;
.source "SourceFile"


# virtual methods
.method public final OooO()Ljava/lang/String;
    .locals 1

    const-string v0, "proto_idx"

    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    iget-object v1, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ce7;->OooOOOo(Llyiahf/vczjk/au1;)V

    iget-object v0, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    iget-object v0, v0, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object v0, v0, Llyiahf/vczjk/xt1;->OooOOO0:Llyiahf/vczjk/zt1;

    iget-object v1, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ce7;->OooOOOO(Llyiahf/vczjk/zt1;)V

    iget-object v0, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    check-cast v0, Llyiahf/vczjk/wt1;

    iget-object v0, v0, Llyiahf/vczjk/wt1;->OooOOOO:Llyiahf/vczjk/he7;

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0oO:Llyiahf/vczjk/ce7;

    monitor-enter p1

    if-eqz v0, :cond_1

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/bc8;->OooO0oO()V

    iget-object v1, p1, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v1, Ljava/util/TreeMap;

    invoke-virtual {v1, v0}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/be7;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/be7;

    invoke-direct {v1, v0}, Llyiahf/vczjk/be7;-><init>(Llyiahf/vczjk/he7;)V

    iget-object v2, p1, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Ljava/util/TreeMap;

    invoke-virtual {v2, v0, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit p1

    return-void

    :cond_1
    :try_start_1
    new-instance v0, Ljava/lang/NullPointerException;

    const-string v1, "prototype == null"

    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw v0

    :goto_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOOo:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/t92;)I
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0oO:Llyiahf/vczjk/ce7;

    iget-object v0, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    check-cast v0, Llyiahf/vczjk/wt1;

    iget-object v0, v0, Llyiahf/vczjk/wt1;->OooOOOO:Llyiahf/vczjk/he7;

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object p1, p1, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast p1, Ljava/util/TreeMap;

    invoke-virtual {p1, v0}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/be7;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/gx3;->OooO0o0()I

    move-result p1

    return p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "not found"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "prototype == null"

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
