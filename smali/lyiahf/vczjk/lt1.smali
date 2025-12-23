.class public final Llyiahf/vczjk/lt1;
.super Llyiahf/vczjk/vt1;
.source "SourceFile"


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/hj1;)I
    .locals 3

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/vt1;

    iget-object v1, v0, Llyiahf/vczjk/vt1;->OooOOO0:Llyiahf/vczjk/au1;

    iget-object v2, p0, Llyiahf/vczjk/vt1;->OooOOO0:Llyiahf/vczjk/au1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v2, Llyiahf/vczjk/xt1;->OooOOO0:Llyiahf/vczjk/zt1;

    iget-object v0, v0, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object v0, v0, Llyiahf/vczjk/xt1;->OooOOO0:Llyiahf/vczjk/zt1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result v1

    :goto_0
    if-eqz v1, :cond_1

    return v1

    :cond_1
    check-cast p1, Llyiahf/vczjk/lt1;

    iget-object v0, v2, Llyiahf/vczjk/xt1;->OooOOO:Llyiahf/vczjk/zt1;

    iget-object p1, p1, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object p1, p1, Llyiahf/vczjk/xt1;->OooOOO:Llyiahf/vczjk/zt1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result p1

    return p1
.end method

.method public final OooO0o0()Ljava/lang/String;
    .locals 1

    const-string v0, "field"

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/p1a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object v0, v0, Llyiahf/vczjk/xt1;->OooOOO:Llyiahf/vczjk/zt1;

    iget-object v0, v0, Llyiahf/vczjk/zt1;->OooOOO0:Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/p1a;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/p1a;

    move-result-object v0

    return-object v0
.end method
