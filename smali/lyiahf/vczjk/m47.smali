.class public final Llyiahf/vczjk/m47;
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

    check-cast p1, [S

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0o()Llyiahf/vczjk/ex9;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wx;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/wx;

    const/4 v2, 0x6

    invoke-direct {v1, v2}, Llyiahf/vczjk/wx;-><init>(I)V

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOO:Ljava/lang/Object;

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/ex9;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wx;

    invoke-virtual {v0}, Llyiahf/vczjk/wx;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [S

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    :try_start_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v4, v5, :cond_6

    sget-object v5, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_3

    iget-object v4, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-eqz v4, :cond_2

    invoke-interface {v4, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    goto :goto_0

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_2
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->Oooo0o0(Llyiahf/vczjk/v72;)V

    move v4, v2

    goto :goto_1

    :cond_3
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result v4

    const/16 v5, -0x8000

    if-lt v4, v5, :cond_5

    const/16 v5, 0x7fff

    if-gt v4, v5, :cond_5

    int-to-short v4, v4

    :goto_1
    array-length v5, v1

    if-lt v3, v5, :cond_4

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0O0(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, [S
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move v3, v2

    move-object v1, v5

    :cond_4
    add-int/lit8 v5, v3, 0x1

    :try_start_1
    aput-short v4, v1, v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v3, v5

    goto :goto_0

    :catch_1
    move-exception p1

    move v3, v5

    goto :goto_2

    :cond_5
    :try_start_2
    iget-object p2, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v4

    new-array v2, v2, [Ljava/lang/Object;

    const-string v5, "overflow, value cannot be represented as 16-bit value"

    invoke-virtual {p1, p2, v4, v5, v2}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    :cond_6
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/wx;->OooO0OO(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [S

    return-object p1

    :goto_2
    iget p2, v0, Llyiahf/vczjk/wx;->OooO0Oo:I

    add-int/2addr p2, v3

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, [S

    check-cast p2, [S

    array-length v0, p1

    array-length v1, p2

    add-int v2, v0, v1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([SI)[S

    move-result-object p1

    const/4 v2, 0x0

    invoke-static {p2, v2, p1, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [S

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    const/4 v0, 0x0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result p2

    const/16 v1, -0x8000

    if-lt p2, v1, :cond_0

    const/16 v1, 0x7fff

    if-gt p2, v1, :cond_0

    int-to-short p1, p2

    const/4 p2, 0x1

    new-array p2, p2, [S

    aput-short p1, p2, v0

    return-object p2

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p2

    new-array v0, v0, [Ljava/lang/Object;

    const-string v2, "overflow, value cannot be represented as 16-bit value"

    invoke-virtual {p1, v1, p2, v2, v0}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
    .locals 1

    new-instance v0, Llyiahf/vczjk/m47;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/n47;-><init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
