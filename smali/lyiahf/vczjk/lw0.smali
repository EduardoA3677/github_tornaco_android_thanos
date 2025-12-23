.class public final Llyiahf/vczjk/lw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf5;


# virtual methods
.method public final OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 5

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    goto :goto_1

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v1

    const/4 v2, 0x1

    if-gt v2, v1, :cond_2

    :goto_0
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ef5;

    invoke-interface {v3, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v3, p1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    move-result v4

    if-lez v4, :cond_1

    move-object p1, v3

    :cond_1
    if-eq v2, v1, :cond_2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    return p1

    :cond_3
    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 17

    move-object/from16 v0, p2

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    const/4 v4, 0x0

    if-ge v3, v1, :cond_1

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/ef5;

    invoke-static {v6}, Landroidx/compose/ui/layout/OooO00o;->OooO00o(Llyiahf/vczjk/ef5;)Ljava/lang/Object;

    move-result-object v6

    const-string v7, "leadingIcon"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    move-object v5, v4

    :goto_1
    check-cast v5, Llyiahf/vczjk/ef5;

    if-eqz v5, :cond_2

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/16 v12, 0xa

    move-wide/from16 v6, p3

    invoke-static/range {v6 .. v12}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v8

    invoke-interface {v5, v8, v9}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v1

    move-object v6, v1

    goto :goto_2

    :cond_2
    move-object v6, v4

    :goto_2
    if-eqz v6, :cond_3

    iget v1, v6, Llyiahf/vczjk/ow6;->OooOOO0:I

    goto :goto_3

    :cond_3
    move v1, v2

    :goto_3
    if-eqz v6, :cond_4

    iget v3, v6, Llyiahf/vczjk/ow6;->OooOOO:I

    move v7, v3

    goto :goto_4

    :cond_4
    move v7, v2

    :goto_4
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v3

    move v5, v2

    :goto_5
    if-ge v5, v3, :cond_6

    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/ef5;

    invoke-static {v9}, Landroidx/compose/ui/layout/OooO00o;->OooO00o(Llyiahf/vczjk/ef5;)Ljava/lang/Object;

    move-result-object v9

    const-string v10, "trailingIcon"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    goto :goto_6

    :cond_5
    add-int/lit8 v5, v5, 0x1

    goto :goto_5

    :cond_6
    move-object v8, v4

    :goto_6
    check-cast v8, Llyiahf/vczjk/ef5;

    if-eqz v8, :cond_7

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v16, 0xa

    move-wide/from16 v10, p3

    invoke-static/range {v10 .. v16}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v3

    invoke-interface {v8, v3, v4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v4

    :cond_7
    move-object v11, v4

    if-eqz v11, :cond_8

    iget v3, v11, Llyiahf/vczjk/ow6;->OooOOO0:I

    goto :goto_7

    :cond_8
    move v3, v2

    :goto_7
    if-eqz v11, :cond_9

    iget v4, v11, Llyiahf/vczjk/ow6;->OooOOO:I

    move v12, v4

    goto :goto_8

    :cond_9
    move v12, v2

    :goto_8
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v4

    move v5, v2

    :goto_9
    if-ge v5, v4, :cond_b

    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ef5;

    invoke-static {v8}, Landroidx/compose/ui/layout/OooO00o;->OooO00o(Llyiahf/vczjk/ef5;)Ljava/lang/Object;

    move-result-object v9

    const-string v10, "label"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_a

    add-int v0, v1, v3

    neg-int v0, v0

    const/4 v4, 0x2

    move-wide/from16 v9, p3

    invoke-static {v0, v2, v9, v10, v4}, Llyiahf/vczjk/uk1;->OooOO0(IIJI)J

    move-result-wide v4

    invoke-interface {v8, v4, v5}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v9

    iget v0, v9, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v0, v1

    add-int/2addr v0, v3

    iget v2, v9, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v2, v12}, Ljava/lang/Math;->max(II)I

    move-result v2

    invoke-static {v7, v2}, Ljava/lang/Math;->max(II)I

    move-result v8

    new-instance v5, Llyiahf/vczjk/kw0;

    move v10, v1

    invoke-direct/range {v5 .. v12}, Llyiahf/vczjk/kw0;-><init>(Llyiahf/vczjk/ow6;IILlyiahf/vczjk/ow6;ILlyiahf/vczjk/ow6;I)V

    sget-object v1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    move-object/from16 v6, p1

    invoke-interface {v6, v0, v8, v1, v5}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object v0

    return-object v0

    :cond_a
    move-wide/from16 v9, p3

    move v8, v7

    move v7, v1

    move-object v1, v6

    move-object/from16 v6, p1

    add-int/lit8 v5, v5, 0x1

    move-object v6, v1

    move v1, v7

    move v7, v8

    goto :goto_9

    :cond_b
    const-string v0, "Collection contains no element matching the predicate."

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo0o(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v0

    throw v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p1

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    if-ge v0, p1, :cond_0

    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result v2

    add-int/2addr v1, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return v1
.end method

.method public final OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p1

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    if-ge v0, p1, :cond_0

    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result v2

    add-int/2addr v1, v2

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return v1
.end method

.method public final OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 5

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    goto :goto_1

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v1

    const/4 v2, 0x1

    if-gt v2, v1, :cond_2

    :goto_0
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ef5;

    invoke-interface {v3, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v3, p1}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    move-result v4

    if-lez v4, :cond_1

    move-object p1, v3

    :cond_1
    if-eq v2, v1, :cond_2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    :goto_1
    if-eqz p1, :cond_3

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    return p1

    :cond_3
    return v0
.end method
