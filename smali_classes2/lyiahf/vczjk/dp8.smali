.class public abstract Llyiahf/vczjk/dp8;
.super Llyiahf/vczjk/iaa;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gp8;
.implements Llyiahf/vczjk/c3a;


# virtual methods
.method public bridge synthetic o00000OO(Z)Llyiahf/vczjk/iaa;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method

.method public abstract o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
.end method

.method public abstract o0000Ooo(Z)Llyiahf/vczjk/dp8;
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/un;

    sget-object v3, Llyiahf/vczjk/h72;->OooO0o0:Llyiahf/vczjk/h72;

    const/4 v4, 0x0

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/h72;->OooOo(Llyiahf/vczjk/un;Llyiahf/vczjk/fo;)Ljava/lang/String;

    move-result-object v2

    const-string v3, "] "

    const-string v4, "["

    filled-new-array {v4, v2, v3}, [Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    :goto_0
    const/4 v4, 0x3

    if-ge v3, v4, :cond_0

    aget-object v4, v2, v3

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    const-string v4, ">"

    const/4 v5, 0x0

    const-string v2, ", "

    const-string v3, "<"

    const/16 v6, 0x70

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/d21;->o0ooOOo(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)V

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    if-eqz v0, :cond_3

    const-string v0, "?"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_3
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
