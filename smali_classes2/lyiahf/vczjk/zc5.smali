.class public final Llyiahf/vczjk/zc5;
.super Llyiahf/vczjk/ye5;
.source "SourceFile"


# virtual methods
.method public final OooOoo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/xc5;)V
    .locals 4

    iget-object p1, p2, Llyiahf/vczjk/xc5;->OooOOo0:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    new-instance p1, Llyiahf/vczjk/xp3;

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    const/4 v1, 0x0

    const/4 v2, 0x0

    const-string v3, ""

    invoke-direct {p1, v3, v1, v0, v2}, Llyiahf/vczjk/xp3;-><init>(Ljava/lang/String;ILjava/util/Map;Llyiahf/vczjk/xp3;)V

    iput-object p1, p2, Llyiahf/vczjk/xc5;->OooOOo:Llyiahf/vczjk/xp3;

    return-void
.end method

.method public final Oooo0(Ljava/lang/String;)Llyiahf/vczjk/ze9;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method
