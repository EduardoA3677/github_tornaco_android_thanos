.class public final Llyiahf/vczjk/zj0;
.super Llyiahf/vczjk/wp3;
.source "SourceFile"


# virtual methods
.method public final OooOO0O(Llyiahf/vczjk/wd;)Ljava/util/List;
    .locals 3

    const/4 v0, 0x0

    new-instance v1, Llyiahf/vczjk/a61;

    invoke-direct {v1, v0}, Llyiahf/vczjk/a61;-><init>(I)V

    new-instance v2, Llyiahf/vczjk/m12;

    invoke-direct {v2, p1}, Llyiahf/vczjk/m12;-><init>(Llyiahf/vczjk/wd;)V

    const/4 p1, 0x2

    new-array p1, p1, [Llyiahf/vczjk/xn0;

    aput-object v1, p1, v0

    const/4 v0, 0x1

    aput-object v2, p1, v0

    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o()Ljava/util/List;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yj0;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/yj0;-><init>(I)V

    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
