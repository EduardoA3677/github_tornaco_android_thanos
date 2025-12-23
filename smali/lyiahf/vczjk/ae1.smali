.class public final Llyiahf/vczjk/ae1;
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
        "Llyiahf/vczjk/ae1;",
        "Llyiahf/vczjk/sy5;",
        "Llyiahf/vczjk/zd1;",
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
    value = "composable"
.end annotation


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ae1;->OooO0OO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/av5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/zd1;

    sget-object v1, Llyiahf/vczjk/z91;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/zd1;-><init>(Llyiahf/vczjk/ae1;Llyiahf/vczjk/a91;)V

    return-object v0
.end method

.method public final OooO0Oo(Ljava/util/List;Llyiahf/vczjk/bw5;)V
    .locals 5

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_6

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ku5;

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    const-string v1, "backStackEntry"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/pu5;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    instance-of v3, v2, Ljava/util/Collection;

    iget-object v4, v0, Llyiahf/vczjk/pu5;->OooO0o0:Llyiahf/vczjk/gh7;

    if-eqz v3, :cond_0

    move-object v3, v2

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_1

    :cond_0
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ku5;

    if-ne v3, p2, :cond_1

    iget-object v2, v4, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    instance-of v3, v2, Ljava/util/Collection;

    if-eqz v3, :cond_2

    move-object v3, v2

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_1

    :cond_2
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ku5;

    if-ne v3, p2, :cond_3

    goto :goto_0

    :cond_4
    :goto_1
    iget-object v2, v4, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-static {v2}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ku5;

    const/4 v3, 0x0

    if-eqz v2, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/Set;

    invoke-static {v4, v2}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v2

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Set;

    invoke-static {v2, p2}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v2

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-virtual {v0, p2}, Llyiahf/vczjk/pu5;->OooO0o(Llyiahf/vczjk/ku5;)V

    goto/16 :goto_0

    :cond_6
    iget-object p1, p0, Llyiahf/vczjk/ae1;->OooO0OO:Llyiahf/vczjk/qs5;

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/ku5;Z)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/pu5;->OooO0o0(Llyiahf/vczjk/ku5;Z)V

    iget-object p1, p0, Llyiahf/vczjk/ae1;->OooO0OO:Llyiahf/vczjk/qs5;

    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0oO(Llyiahf/vczjk/ku5;)V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    const-string v1, "entry"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/pu5;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Set;

    invoke-static {v2, p1}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    iget-object v0, v0, Llyiahf/vczjk/pu5;->OooO0oo:Llyiahf/vczjk/ov5;

    iget-object v0, v0, Llyiahf/vczjk/ov5;->OooO0O0:Llyiahf/vczjk/su5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/su5;->OooO0o:Llyiahf/vczjk/xx;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xx;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOOo:Llyiahf/vczjk/jy4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ku5;->OooO0O0(Llyiahf/vczjk/jy4;)V

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Cannot transition entry that is not in the back stack"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
