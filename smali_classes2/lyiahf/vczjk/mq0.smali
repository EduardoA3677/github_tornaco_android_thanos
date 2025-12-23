.class public final Llyiahf/vczjk/mq0;
.super Llyiahf/vczjk/p3a;
.source "SourceFile"


# virtual methods
.method public final OooO0oO(Llyiahf/vczjk/n3a;)Llyiahf/vczjk/z4a;
    .locals 2

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/nq0;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/nq0;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-nez p1, :cond_1

    return-object v1

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/nq0;->OooO0o0()Llyiahf/vczjk/z4a;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_2

    new-instance v0, Llyiahf/vczjk/f19;

    sget-object v1, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    invoke-interface {p1}, Llyiahf/vczjk/nq0;->OooO0o0()Llyiahf/vczjk/z4a;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object v0

    :cond_2
    invoke-interface {p1}, Llyiahf/vczjk/nq0;->OooO0o0()Llyiahf/vczjk/z4a;

    move-result-object p1

    return-object p1
.end method
