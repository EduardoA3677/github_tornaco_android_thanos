.class public final Llyiahf/vczjk/j47;
.super Llyiahf/vczjk/n47;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n47;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [F

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0o()Llyiahf/vczjk/ex9;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wx;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/wx;

    const/4 v2, 0x3

    invoke-direct {v1, v2}, Llyiahf/vczjk/wx;-><init>(I)V

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo:Ljava/lang/Object;

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/ex9;->OooOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wx;

    invoke-virtual {v0}, Llyiahf/vczjk/wx;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [F

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    :try_start_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v4, v5, :cond_4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_2

    iget-object v4, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-eqz v4, :cond_2

    invoke-interface {v4, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_1

    :cond_2
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo000(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)F

    move-result v4

    array-length v5, v1

    if-lt v3, v5, :cond_3

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0O0(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, [F
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v3, v2

    move-object v1, v5

    :cond_3
    add-int/lit8 v5, v3, 0x1

    :try_start_1
    aput v4, v1, v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v3, v5

    goto :goto_0

    :catch_1
    move-exception p1

    move v3, v5

    goto :goto_1

    :cond_4
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0OO(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [F

    return-object p1

    :goto_1
    iget p2, v0, Llyiahf/vczjk/wx;->OooO0Oo:I

    add-int/2addr p2, v3

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, [F

    check-cast p2, [F

    array-length v0, p1

    array-length v1, p2

    add-int v2, v0, v1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([FI)[F

    move-result-object p1

    const/4 v2, 0x0

    invoke-static {p2, v2, p1, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [F

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo000(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)F

    move-result p1

    const/4 p2, 0x1

    new-array p2, p2, [F

    const/4 v0, 0x0

    aput p1, p2, v0

    return-object p2
.end method

.method public final OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
    .locals 1

    new-instance v0, Llyiahf/vczjk/j47;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/n47;-><init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
