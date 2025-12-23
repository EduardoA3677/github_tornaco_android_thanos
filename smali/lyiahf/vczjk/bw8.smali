.class public abstract Llyiahf/vczjk/bw8;
.super Llyiahf/vczjk/c39;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qr5;
.implements Llyiahf/vczjk/dw8;


# instance fields
.field public OooOOO:Llyiahf/vczjk/aw8;


# virtual methods
.method public final OooO(Llyiahf/vczjk/d39;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/aw8;

    iput-object p1, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;
    .locals 0

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/aw8;

    check-cast p3, Llyiahf/vczjk/aw8;

    iget p1, p1, Llyiahf/vczjk/aw8;->OooO0OO:I

    iget p3, p3, Llyiahf/vczjk/aw8;->OooO0OO:I

    if-ne p1, p3, :cond_0

    return-object p2

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0O0()Llyiahf/vczjk/d39;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/gw8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    return-object v0
.end method

.method public final OooOOoo()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    invoke-static {v0, p0}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/aw8;

    iget v0, v0, Llyiahf/vczjk/aw8;->OooO0OO:I

    return v0
.end method

.method public final OooOo00(I)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/aw8;

    iget v1, v0, Llyiahf/vczjk/aw8;->OooO0OO:I

    if-eq v1, p1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    sget-object v2, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v3

    invoke-static {v1, p0, v3, v0}, Llyiahf/vczjk/vv8;->OooOOOO(Llyiahf/vczjk/d39;Llyiahf/vczjk/c39;Llyiahf/vczjk/nv8;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/aw8;

    iput p1, v0, Llyiahf/vczjk/aw8;->OooO0OO:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v2

    invoke-static {v3, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v2

    throw p1

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/bw8;->OooOOO:Llyiahf/vczjk/aw8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/aw8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "MutableIntState(value="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v0, v0, Llyiahf/vczjk/aw8;->OooO0OO:I

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, ")@"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
