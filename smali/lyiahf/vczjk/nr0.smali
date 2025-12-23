.class public final enum Llyiahf/vczjk/nr0;
.super Llyiahf/vczjk/or0;
.source "SourceFile"


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/or0;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    sget-object v0, Llyiahf/vczjk/or0;->OooOOO0:Llyiahf/vczjk/jr0;

    if-ne p1, v0, :cond_0

    const/16 p1, 0x5f

    const/16 v0, 0x2d

    invoke-virtual {p2, p1, v0}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooooO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/or0;->OooOOO:Llyiahf/vczjk/kr0;

    if-ne p1, v0, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/u34;->OooooO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/or0;->OooO0O0(Llyiahf/vczjk/or0;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooooOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
