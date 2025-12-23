.class public final Llyiahf/vczjk/or7;
.super Llyiahf/vczjk/o0o0Oo;
.source "SourceFile"


# virtual methods
.method public final OooO(Ljava/lang/Throwable;)Z
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method

.method public final OooOO0(Ljava/lang/Object;)Z
    .locals 2

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/o0o0Oo;->OooOOoo:Ljava/lang/Object;

    :cond_0
    sget-object v0, Llyiahf/vczjk/o0o0Oo;->OooOOo:Llyiahf/vczjk/e16;

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/e16;->OooOOOO(Llyiahf/vczjk/o0o0Oo;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/o0o0Oo;->OooO0OO(Llyiahf/vczjk/o0o0Oo;)V

    const/4 p1, 0x1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method
