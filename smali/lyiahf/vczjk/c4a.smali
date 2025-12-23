.class public final Llyiahf/vczjk/c4a;
.super Llyiahf/vczjk/fu3;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/t92;)V
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    iget-object v0, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    invoke-virtual {v0}, Llyiahf/vczjk/au1;->OooO0o()Llyiahf/vczjk/zt1;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ce7;->OooOOOO(Llyiahf/vczjk/zt1;)V

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOOOO:Llyiahf/vczjk/i54;

    return-object v0
.end method

.method public final OooO0OO()I
    .locals 1

    const/4 v0, 0x4

    return v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    invoke-virtual {v0}, Llyiahf/vczjk/au1;->OooO0o()Llyiahf/vczjk/zt1;

    move-result-object v0

    iget-object p1, p1, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ce7;->OooOO0o(Llyiahf/vczjk/zt1;)I

    move-result p1

    invoke-virtual {p2}, Llyiahf/vczjk/ol0;->OooO0Oo()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/gx3;->OooO0o()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/zt1;->OooO00o()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " "

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {p2, v1, v0}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v0

    const-string v1, "  descriptor_idx: "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x4

    invoke-virtual {p2, v1, v0}, Llyiahf/vczjk/ol0;->OooO0O0(ILjava/lang/String;)V

    :cond_0
    invoke-virtual {p2, p1}, Llyiahf/vczjk/ol0;->OooOO0(I)V

    return-void
.end method
