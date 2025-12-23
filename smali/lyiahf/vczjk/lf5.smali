.class public interface abstract Llyiahf/vczjk/lf5;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ef5;

    new-instance v5, Llyiahf/vczjk/l22;

    sget-object v6, Llyiahf/vczjk/p34;->OooOOO:Llyiahf/vczjk/p34;

    sget-object v7, Llyiahf/vczjk/s34;->OooOOO:Llyiahf/vczjk/s34;

    const/4 v8, 0x0

    invoke-direct {v5, v4, v6, v7, v8}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    const/16 p2, 0xd

    invoke-static {p3, v2, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v1, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v1, v0, p2, p3}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
.end method

.method public OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ef5;

    new-instance v5, Llyiahf/vczjk/l22;

    sget-object v6, Llyiahf/vczjk/p34;->OooOOO0:Llyiahf/vczjk/p34;

    sget-object v7, Llyiahf/vczjk/s34;->OooOOO0:Llyiahf/vczjk/s34;

    const/4 v8, 0x0

    invoke-direct {v5, v4, v6, v7, v8}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    const/4 p2, 0x7

    invoke-static {v2, p3, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v1, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v1, v0, p2, p3}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ef5;

    new-instance v5, Llyiahf/vczjk/l22;

    sget-object v6, Llyiahf/vczjk/p34;->OooOOO:Llyiahf/vczjk/p34;

    sget-object v7, Llyiahf/vczjk/s34;->OooOOO0:Llyiahf/vczjk/s34;

    const/4 v8, 0x0

    invoke-direct {v5, v4, v6, v7, v8}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    const/4 p2, 0x7

    invoke-static {v2, p3, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v1, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v1, v0, p2, p3}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 9

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_0

    invoke-interface {p2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ef5;

    new-instance v5, Llyiahf/vczjk/l22;

    sget-object v6, Llyiahf/vczjk/p34;->OooOOO0:Llyiahf/vczjk/p34;

    sget-object v7, Llyiahf/vczjk/s34;->OooOOO:Llyiahf/vczjk/s34;

    const/4 v8, 0x0

    invoke-direct {v5, v4, v6, v7, v8}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    const/16 p2, 0xd

    invoke-static {p3, v2, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v1, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v2

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {p0, v1, v0, p2, p3}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method
