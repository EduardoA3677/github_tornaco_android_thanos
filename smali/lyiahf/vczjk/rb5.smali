.class public final Llyiahf/vczjk/rb5;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Ljava/lang/Object;Ljava/lang/Object;)Llyiahf/vczjk/qb5;
    .locals 1

    check-cast p0, Llyiahf/vczjk/qb5;

    check-cast p1, Llyiahf/vczjk/qb5;

    invoke-virtual {p1}, Ljava/util/AbstractMap;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/qb5;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/qb5;->OooO0o0()Llyiahf/vczjk/qb5;

    move-result-object p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/qb5;->OooO00o()V

    invoke-virtual {p1}, Ljava/util/AbstractMap;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/qb5;->putAll(Ljava/util/Map;)V

    :cond_1
    return-object p0
.end method
