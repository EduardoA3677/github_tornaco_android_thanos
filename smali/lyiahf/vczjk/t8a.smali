.class public abstract Llyiahf/vczjk/t8a;
.super Llyiahf/vczjk/bc8;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/y44;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/gx3;

    invoke-virtual {p1}, Llyiahf/vczjk/gx3;->OooO0o0()I

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/y44;->OooO0OO()I

    move-result p1

    mul-int/2addr p1, v0

    if-ltz p1, :cond_1

    iget v0, p0, Llyiahf/vczjk/bc8;->OooO0Oo:I

    if-ltz v0, :cond_0

    add-int/2addr v0, p1

    return v0

    :cond_0
    new-instance p1, Ljava/lang/RuntimeException;

    const-string v0, "fileOffset not yet set"

    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "relative < 0"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o0()V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/t8a;->OooOO0O()V

    invoke-virtual {p0}, Llyiahf/vczjk/bc8;->OooO0OO()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/y44;

    iget-object v2, p0, Llyiahf/vczjk/bc8;->OooO0O0:Llyiahf/vczjk/t92;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/y44;->OooO00o(Llyiahf/vczjk/t92;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final OooO0oo()I
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/bc8;->OooO0OO()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v1

    if-nez v1, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/y44;

    invoke-virtual {v0}, Llyiahf/vczjk/y44;->OooO0OO()I

    move-result v0

    mul-int/2addr v0, v1

    return v0
.end method

.method public final OooOO0(Llyiahf/vczjk/ol0;)V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/bc8;->OooO0OO()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/y44;

    iget-object v2, p0, Llyiahf/vczjk/bc8;->OooO0O0:Llyiahf/vczjk/t92;

    invoke-virtual {v1, v2, p1}, Llyiahf/vczjk/y44;->OooO0Oo(Llyiahf/vczjk/t92;Llyiahf/vczjk/ol0;)V

    iget v1, p0, Llyiahf/vczjk/bc8;->OooO0OO:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ol0;->OooO00o(I)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public abstract OooOO0O()V
.end method
