.class public final Llyiahf/vczjk/hr9;
.super Llyiahf/vczjk/xa0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooOOOo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/e94;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hr9;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ya0;-><init>(Llyiahf/vczjk/ya0;Llyiahf/vczjk/wt5;)V

    return-object v0
.end method

.method public final o0ooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xa0;->OoooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ya0;->_beanType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-nez v0, :cond_10

    iget-object v0, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO0oO()Z

    move-result v0

    iget-object v3, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v3}, Llyiahf/vczjk/nca;->OooO()Z

    move-result v3

    if-nez v0, :cond_3

    if-eqz v3, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OooOOO0()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->Oooooo()Llyiahf/vczjk/nca;

    move-result-object v0

    const-string v3, "Throwable needs a default constructor, a single-String-arg constructor; or explicit @JsonCreator"

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v0, v3, v2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1

    :cond_3
    :goto_0
    move-object v3, v1

    move-object v4, v3

    move v5, v2

    :goto_1
    sget-object v6, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v6}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v6

    if-nez v6, :cond_c

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/fb0;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    if-eqz v7, :cond_6

    if-eqz v3, :cond_4

    invoke-virtual {v7, p2, p1, v3}, Llyiahf/vczjk/ph8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V

    goto :goto_3

    :cond_4
    if-nez v4, :cond_5

    iget-object v4, p0, Llyiahf/vczjk/ya0;->_beanProperties:Llyiahf/vczjk/fb0;

    invoke-virtual {v4}, Llyiahf/vczjk/fb0;->size()I

    move-result v4

    add-int/2addr v4, v4

    new-array v4, v4, [Ljava/lang/Object;

    :cond_5
    add-int/lit8 v6, v5, 0x1

    aput-object v7, v4, v5

    add-int/lit8 v5, v5, 0x2

    invoke-virtual {v7, p1, p2}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v7

    aput-object v7, v4, v6

    goto :goto_3

    :cond_6
    const-string v7, "message"

    invoke-virtual {v7, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    if-eqz v0, :cond_8

    iget-object v3, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000OOo()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v3, v6, p1}, Llyiahf/vczjk/nca;->OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v4, :cond_b

    move v6, v2

    :goto_2
    if-ge v6, v5, :cond_7

    aget-object v7, v4, v6

    check-cast v7, Llyiahf/vczjk/ph8;

    add-int/lit8 v8, v6, 0x1

    aget-object v8, v4, v8

    invoke-virtual {v7, v3, v8}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    add-int/lit8 v6, v6, 0x2

    goto :goto_2

    :cond_7
    move-object v4, v1

    goto :goto_3

    :cond_8
    iget-object v7, p0, Llyiahf/vczjk/ya0;->_ignorableProps:Ljava/util/Set;

    if-eqz v7, :cond_9

    invoke-interface {v7, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_9

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_3

    :cond_9
    iget-object v7, p0, Llyiahf/vczjk/ya0;->_anySetter:Llyiahf/vczjk/nh8;

    if-eqz v7, :cond_a

    invoke-virtual {v7, v3, v6, p1, p2}, Llyiahf/vczjk/nh8;->OooO0O0(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    goto :goto_3

    :cond_a
    invoke-virtual {p0, v3, v6, p1, p2}, Llyiahf/vczjk/ya0;->ooOO(Ljava/lang/Object;Ljava/lang/String;Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    :cond_b
    :goto_3
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    goto :goto_1

    :cond_c
    if-nez v3, :cond_f

    if-eqz v0, :cond_d

    iget-object p2, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2, v1, p1}, Llyiahf/vczjk/nca;->OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_4

    :cond_d
    iget-object p2, p0, Llyiahf/vczjk/ya0;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    :goto_4
    if-eqz v4, :cond_e

    :goto_5
    if-ge v2, v5, :cond_e

    aget-object p2, v4, v2

    check-cast p2, Llyiahf/vczjk/ph8;

    add-int/lit8 v0, v2, 0x1

    aget-object v0, v4, v0

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    add-int/lit8 v2, v2, 0x2

    goto :goto_5

    :cond_e
    return-object p1

    :cond_f
    return-object v3

    :cond_10
    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->OooOOO0()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p0}, Llyiahf/vczjk/ya0;->Oooooo()Llyiahf/vczjk/nca;

    move-result-object v0

    const-string v3, "abstract type (need to add/enable type information?)"

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v0, v3, v2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1
.end method
