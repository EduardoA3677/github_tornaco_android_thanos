.class public final Llyiahf/vczjk/jo;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ko;


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/hc3;)Z
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->Oooo0oo(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Z

    move-result p1

    return p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final isEmpty()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    sget-object v0, Llyiahf/vczjk/zm2;->OooOOO0:Llyiahf/vczjk/zm2;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "EMPTY"

    return-object v0
.end method
