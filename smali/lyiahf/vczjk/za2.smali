.class public final Llyiahf/vczjk/za2;
.super Llyiahf/vczjk/sy5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/sy5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "Llyiahf/vczjk/za2;",
        "Llyiahf/vczjk/sy5;",
        "Llyiahf/vczjk/ya2;",
        "<init>",
        "()V",
        "navigation-compose_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Llyiahf/vczjk/ry5;
    value = "dialog"
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/av5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ya2;

    sget-object v1, Llyiahf/vczjk/ha1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ya2;-><init>(Llyiahf/vczjk/za2;)V

    return-object v0
.end method

.method public final OooO0Oo(Ljava/util/List;Llyiahf/vczjk/bw5;)V
    .locals 1

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ku5;

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/pu5;->OooO0o(Llyiahf/vczjk/ku5;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/ku5;Z)V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/pu5;->OooO0o0(Llyiahf/vczjk/ku5;Z)V

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object p2

    iget-object p2, p2, Llyiahf/vczjk/pu5;->OooO0o:Llyiahf/vczjk/gh7;

    iget-object p2, p2, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p2, Llyiahf/vczjk/s29;

    invoke-virtual {p2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Iterable;

    invoke-static {p2, p1}, Llyiahf/vczjk/d21;->o00oO0O(Ljava/lang/Iterable;Ljava/lang/Object;)I

    move-result p1

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object p2

    iget-object p2, p2, Llyiahf/vczjk/pu5;->OooO0o:Llyiahf/vczjk/gh7;

    iget-object p2, p2, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p2, Llyiahf/vczjk/s29;

    invoke-virtual {p2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Iterable;

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    const/4 v0, 0x0

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    add-int/lit8 v2, v0, 0x1

    if-ltz v0, :cond_1

    check-cast v1, Llyiahf/vczjk/ku5;

    if-le v0, p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pu5;->OooO0OO(Llyiahf/vczjk/ku5;)V

    :cond_0
    move v0, v2

    goto :goto_0

    :cond_1
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    const/4 p1, 0x0

    throw p1

    :cond_2
    return-void
.end method
