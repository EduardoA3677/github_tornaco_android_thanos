.class public final Llyiahf/vczjk/rl0;
.super Llyiahf/vczjk/b59;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, [B

    array-length p1, p2

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    check-cast p1, [B

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object p3

    invoke-virtual {p3}, Llyiahf/vczjk/ec5;->OooO0o()Llyiahf/vczjk/z50;

    move-result-object p3

    array-length v0, p1

    const/4 v1, 0x0

    invoke-virtual {p2, p3, p1, v1, v0}, Llyiahf/vczjk/u94;->o0ooOO0(Llyiahf/vczjk/z50;[BII)V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 3

    check-cast p1, [B

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOoo:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object p3

    invoke-virtual {p3}, Llyiahf/vczjk/ec5;->OooO0o()Llyiahf/vczjk/z50;

    move-result-object p3

    array-length v1, p1

    const/4 v2, 0x0

    invoke-virtual {p2, p3, p1, v2, v1}, Llyiahf/vczjk/u94;->o0ooOO0(Llyiahf/vczjk/z50;[BII)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method
