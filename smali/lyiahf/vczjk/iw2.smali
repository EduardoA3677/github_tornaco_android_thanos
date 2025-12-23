.class public final Llyiahf/vczjk/iw2;
.super Llyiahf/vczjk/jw2;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/jw2;
    .locals 5

    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/bu1;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/bu1;->OooO0o0(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/jr5;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/iw2;

    const-string v1, "cubics"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, p1}, Llyiahf/vczjk/jw2;-><init>(Ljava/util/List;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "Edge"

    return-object v0
.end method
