.class public interface abstract Llyiahf/vczjk/zp5;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 14

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v1, p2

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v7

    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v7

    move v8, v3

    :goto_1
    if-ge v8, v7, :cond_0

    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ef5;

    new-instance v10, Llyiahf/vczjk/l22;

    sget-object v11, Llyiahf/vczjk/p34;->OooOOO:Llyiahf/vczjk/p34;

    sget-object v12, Llyiahf/vczjk/s34;->OooOOO:Llyiahf/vczjk/s34;

    const/4 v13, 0x0

    invoke-direct {v10, v9, v11, v12, v13}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    const/16 v1, 0xd

    move/from16 v2, p3

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v1

    new-instance v3, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v3, v0, v1, v2}, Llyiahf/vczjk/zp5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
.end method

.method public OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 14

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v1, p2

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v7

    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v7

    move v8, v3

    :goto_1
    if-ge v8, v7, :cond_0

    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ef5;

    new-instance v10, Llyiahf/vczjk/l22;

    sget-object v11, Llyiahf/vczjk/p34;->OooOOO0:Llyiahf/vczjk/p34;

    sget-object v12, Llyiahf/vczjk/s34;->OooOOO0:Llyiahf/vczjk/s34;

    const/4 v13, 0x0

    invoke-direct {v10, v9, v11, v12, v13}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x7

    move/from16 v2, p3

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v1

    new-instance v3, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v3, v0, v1, v2}, Llyiahf/vczjk/zp5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 14

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v1, p2

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v7

    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v7

    move v8, v3

    :goto_1
    if-ge v8, v7, :cond_0

    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ef5;

    new-instance v10, Llyiahf/vczjk/l22;

    sget-object v11, Llyiahf/vczjk/p34;->OooOOO:Llyiahf/vczjk/p34;

    sget-object v12, Llyiahf/vczjk/s34;->OooOOO0:Llyiahf/vczjk/s34;

    const/4 v13, 0x0

    invoke-direct {v10, v9, v11, v12, v13}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x7

    move/from16 v2, p3

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v1

    new-instance v3, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v3, v0, v1, v2}, Llyiahf/vczjk/zp5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 14

    new-instance v0, Ljava/util/ArrayList;

    move-object/from16 v1, p2

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v7

    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v7

    move v8, v3

    :goto_1
    if-ge v8, v7, :cond_0

    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ef5;

    new-instance v10, Llyiahf/vczjk/l22;

    sget-object v11, Llyiahf/vczjk/p34;->OooOOO0:Llyiahf/vczjk/p34;

    sget-object v12, Llyiahf/vczjk/s34;->OooOOO:Llyiahf/vczjk/s34;

    const/4 v13, 0x0

    invoke-direct {v10, v9, v11, v12, v13}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    const/16 v1, 0xd

    move/from16 v2, p3

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide v1

    new-instance v3, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v3, v0, v1, v2}, Llyiahf/vczjk/zp5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method
