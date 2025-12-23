.class public final Llyiahf/vczjk/g47;
.super Llyiahf/vczjk/n47;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    const/4 v3, 0x0

    if-ne v0, v1, :cond_1

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0O()Llyiahf/vczjk/z50;

    move-result-object v1

    invoke-virtual {p2, v1}, Llyiahf/vczjk/eb4;->OooOooo(Llyiahf/vczjk/z50;)[B

    move-result-object p1
    :try_end_0
    .catch Llyiahf/vczjk/bb4; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v1

    invoke-virtual {v1}, Llyiahf/vczjk/ib4;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    const-string v4, "base64"

    invoke-virtual {v1, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v4

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    new-array v0, v2, [Ljava/lang/Object;

    const-class v2, [B

    invoke-virtual {p1, v2, p2, v1, v0}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_1
    :goto_0
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOoo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000OOo()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_2

    goto/16 :goto_6

    :cond_2
    instance-of v1, v0, [B

    if-eqz v1, :cond_3

    move-object v3, v0

    check-cast v3, [B

    goto/16 :goto_6

    :cond_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_4

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n47;->OoooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    move-object v3, p1

    check-cast v3, [B

    goto/16 :goto_6

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o00oO0o()Llyiahf/vczjk/ex9;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ex9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wx;

    if-nez v1, :cond_5

    new-instance v1, Llyiahf/vczjk/wx;

    const/4 v4, 0x1

    invoke-direct {v1, v4}, Llyiahf/vczjk/wx;-><init>(I)V

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOO:Ljava/lang/Object;

    :cond_5
    iget-object v0, v0, Llyiahf/vczjk/ex9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wx;

    invoke-virtual {v0}, Llyiahf/vczjk/wx;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [B

    move v4, v2

    :goto_1
    :try_start_1
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v5, v6, :cond_e

    sget-object v6, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-eq v5, v6, :cond_c

    sget-object v6, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    if-ne v5, v6, :cond_6

    goto :goto_4

    :cond_6
    sget-object v6, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v5, v6, :cond_8

    iget-object v5, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-eqz v5, :cond_7

    invoke-interface {v5, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    goto :goto_1

    :catch_1
    move-exception p1

    goto :goto_7

    :cond_7
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->Oooo0o0(Llyiahf/vczjk/v72;)V

    move v5, v2

    goto :goto_5

    :cond_8
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m49;->Oooo00O(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)I

    move-result v5

    const/16 v6, -0x80

    if-lt v5, v6, :cond_a

    const/16 v6, 0xff

    if-le v5, v6, :cond_9

    goto :goto_2

    :cond_9
    move v6, v2

    goto :goto_3

    :cond_a
    :goto_2
    const/4 v6, 0x1

    :goto_3
    if-nez v6, :cond_b

    int-to-byte v5, v5

    goto :goto_5

    :cond_b
    iget-object p2, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v5

    new-array v2, v2, [Ljava/lang/Object;

    const-string v6, "overflow, value cannot be represented as 8-bit value"

    invoke-virtual {p1, p2, v5, v6, v2}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_c
    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooo0oO()B

    move-result v5

    :goto_5
    array-length v6, v1

    if-lt v4, v6, :cond_d

    invoke-virtual {v0, v4, v1}, Llyiahf/vczjk/wx;->OooO0O0(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, [B
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    move v4, v2

    move-object v1, v6

    :cond_d
    add-int/lit8 v6, v4, 0x1

    :try_start_2
    aput-byte v5, v1, v4
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    move v4, v6

    goto :goto_1

    :catch_2
    move-exception p1

    move v4, v6

    goto :goto_7

    :cond_e
    invoke-virtual {v0, v4, v1}, Llyiahf/vczjk/wx;->OooO0OO(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v3, p1

    check-cast v3, [B

    :goto_6
    return-object v3

    :goto_7
    iget p2, v0, Llyiahf/vczjk/wx;->OooO0Oo:I

    add-int/2addr p2, v4

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OoooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, [B

    check-cast p2, [B

    array-length v0, p1

    array-length v1, p2

    add-int v2, v0, v1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    move-result-object p1

    const/4 v2, 0x0

    invoke-static {p2, v2, p1, v0, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-object p1
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [B

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_3

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    sget-object v1, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/n47;->_nuller:Llyiahf/vczjk/u46;

    if-eqz p2, :cond_1

    invoke-interface {p2, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/n47;->OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [B

    return-object p1

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->Oooo0o0(Llyiahf/vczjk/v72;)V

    return-object v2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_3
    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooo0oO()B

    move-result p1

    const/4 p2, 0x1

    new-array p2, p2, [B

    const/4 v0, 0x0

    aput-byte p1, p2, v0

    return-object p2
.end method

.method public final OoooOoo(Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/n47;
    .locals 1

    new-instance v0, Llyiahf/vczjk/g47;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/n47;-><init>(Llyiahf/vczjk/n47;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
