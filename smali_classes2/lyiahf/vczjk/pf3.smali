.class public final Llyiahf/vczjk/pf3;
.super Llyiahf/vczjk/kh3;
.source "SourceFile"


# virtual methods
.method public final OooO0oo()Ljava/util/List;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kh3;->OooO0O0:Llyiahf/vczjk/oo0o0Oo;

    check-cast v0, Llyiahf/vczjk/nf3;

    sget-object v1, Llyiahf/vczjk/xf3;->OooO0OO:Llyiahf/vczjk/xf3;

    iget-object v2, v0, Llyiahf/vczjk/nf3;->OooOOoo:Llyiahf/vczjk/bg3;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/yi4;->Oooo0o0(Llyiahf/vczjk/nf3;Z)Llyiahf/vczjk/uf3;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_0
    sget-object v1, Llyiahf/vczjk/ag3;->OooO0OO:Llyiahf/vczjk/ag3;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 v1, 0x1

    invoke-static {v0, v1}, Llyiahf/vczjk/yi4;->Oooo0o0(Llyiahf/vczjk/nf3;Z)Llyiahf/vczjk/uf3;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method
