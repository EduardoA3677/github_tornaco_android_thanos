.class public final Llyiahf/vczjk/ot9;
.super Llyiahf/vczjk/pt9;
.source "SourceFile"


# virtual methods
.method public final bridge synthetic OooOO0O()Llyiahf/vczjk/vu7;
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/ot9;->OooOo00()Llyiahf/vczjk/pt9;

    return-object p0
.end method

.method public final OooOo00()Llyiahf/vczjk/pt9;
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/pt9;->OooOo00()Llyiahf/vczjk/pt9;

    new-instance v0, Llyiahf/vczjk/n10;

    invoke-direct {v0}, Llyiahf/vczjk/n10;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/pt9;->OooOO0:Llyiahf/vczjk/n10;

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pt9;->OooOO0:Llyiahf/vczjk/n10;

    const-string v1, ">"

    const-string v2, "<"

    if-eqz v0, :cond_0

    iget v0, v0, Llyiahf/vczjk/n10;->OooOOO0:I

    if-lez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/pt9;->OooOOo()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Llyiahf/vczjk/pt9;->OooOO0:Llyiahf/vczjk/n10;

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/pt9;->OooOOo()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
