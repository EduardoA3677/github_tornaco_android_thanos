.class public final Llyiahf/vczjk/c50;
.super Llyiahf/vczjk/e16;
.source "SourceFile"


# instance fields
.field public OooOO0o:Llyiahf/vczjk/rl5;


# virtual methods
.method public final OooOOo0(Llyiahf/vczjk/ie7;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c50;->OooOO0o:Llyiahf/vczjk/rl5;

    invoke-interface {v0}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v0

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOo00(Llyiahf/vczjk/ie7;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/c50;->OooOO0o:Llyiahf/vczjk/rl5;

    invoke-interface {v0}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v0

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, "Check failed."

    invoke-static {p1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/c50;->OooOO0o:Llyiahf/vczjk/rl5;

    invoke-interface {p1}, Llyiahf/vczjk/rl5;->OooO0o0()Llyiahf/vczjk/kna;

    move-result-object p1

    return-object p1
.end method
