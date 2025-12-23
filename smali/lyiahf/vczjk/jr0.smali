.class public final enum Llyiahf/vczjk/jr0;
.super Llyiahf/vczjk/or0;
.source "SourceFile"


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/or0;Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    sget-object v0, Llyiahf/vczjk/or0;->OooOOO:Llyiahf/vczjk/kr0;

    const/16 v1, 0x5f

    const/16 v2, 0x2d

    if-ne p1, v0, :cond_0

    invoke-virtual {p2, v2, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/or0;->OooOOOo:Llyiahf/vczjk/nr0;

    if-ne p1, v0, :cond_1

    invoke-virtual {p2, v2, v1}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooooOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/or0;->OooO0O0(Llyiahf/vczjk/or0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooooO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
