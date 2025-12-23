.class public final Llyiahf/vczjk/gg2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rd1;


# instance fields
.field public OooOOO0:Llyiahf/vczjk/oe3;


# virtual methods
.method public OooO00o(Llyiahf/vczjk/qd2;)V
    .locals 0

    return-void
.end method

.method public OooO0O0(Ljava/util/List;)V
    .locals 7

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/rt3;

    const/4 v0, 0x4

    invoke-direct {v5, v0}, Llyiahf/vczjk/rt3;-><init>(I)V

    const/4 v3, 0x0

    const/4 v4, 0x0

    const-string v2, ""

    const/16 v6, 0x1e

    move-object v1, p1

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/gg2;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public OooO0Oo(Llyiahf/vczjk/qd2;)V
    .locals 0

    return-void
.end method
