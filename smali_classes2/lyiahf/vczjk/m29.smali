.class public final Llyiahf/vczjk/m29;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rl8;


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/c99;)Llyiahf/vczjk/f43;
    .locals 3

    new-instance v0, Llyiahf/vczjk/k29;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/k29;-><init>(Llyiahf/vczjk/m29;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/rs;->OooooOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/et0;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/l29;

    const/4 v2, 0x2

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/w53;

    const/4 v2, 0x0

    invoke-direct {v1, p1, v0, v2}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/m29;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/m29;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    const-wide/16 v0, 0x0

    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    const-wide v1, 0x7fffffffffffffffL

    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 8

    new-instance v0, Llyiahf/vczjk/y05;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/y05;-><init>(I)V

    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "SharingStarted.WhileSubscribed("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/16 v7, 0x3f

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v1

    const/16 v2, 0x29

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
