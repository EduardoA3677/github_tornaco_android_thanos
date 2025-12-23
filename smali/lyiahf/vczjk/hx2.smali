.class public final Llyiahf/vczjk/hx2;
.super Llyiahf/vczjk/dg5;
.source "SourceFile"


# virtual methods
.method public final OooO()Ljava/lang/String;
    .locals 1

    const-string v0, "type_idx"

    return-object v0
.end method

.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    iget-object v1, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ce7;->OooOOOo(Llyiahf/vczjk/au1;)V

    iget-object v0, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    iget-object v1, v0, Llyiahf/vczjk/vt1;->OooOOO:Llyiahf/vczjk/xt1;

    iget-object v1, v1, Llyiahf/vczjk/xt1;->OooOOO0:Llyiahf/vczjk/zt1;

    iget-object v2, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/ce7;->OooOOOO(Llyiahf/vczjk/zt1;)V

    check-cast v0, Llyiahf/vczjk/lt1;

    invoke-virtual {v0}, Llyiahf/vczjk/lt1;->getType()Llyiahf/vczjk/p1a;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ce7;->OooOOo0(Llyiahf/vczjk/p1a;)V

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOOo0:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/t92;)I
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    iget-object v0, p0, Llyiahf/vczjk/dg5;->OooOOOO:Llyiahf/vczjk/vt1;

    check-cast v0, Llyiahf/vczjk/lt1;

    invoke-virtual {v0}, Llyiahf/vczjk/lt1;->getType()Llyiahf/vczjk/p1a;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ce7;->OooOOO(Llyiahf/vczjk/p1a;)I

    move-result p1

    return p1
.end method
