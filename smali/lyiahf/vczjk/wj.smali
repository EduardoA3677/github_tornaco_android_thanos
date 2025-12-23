.class public final Llyiahf/vczjk/wj;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf5;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/wk;

.field public OooO0O0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wk;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wj;->OooO00o:Llyiahf/vczjk/wk;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v0

    const/4 v1, 0x1

    if-gt v1, v0, :cond_2

    :goto_0
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result v2

    if-le v2, p1, :cond_1

    move p1, v2

    :cond_1
    if-eq v1, v0, :cond_2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 7

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    move v4, v3

    :goto_0
    if-ge v2, v1, :cond_0

    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ef5;

    invoke-interface {v5, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v5

    iget v6, v5, Llyiahf/vczjk/ow6;->OooOOO0:I

    invoke-static {v3, v6}, Ljava/lang/Math;->max(II)I

    move-result v3

    iget v6, v5, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v4, v6}, Ljava/lang/Math;->max(II)I

    move-result v4

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result p2

    const-wide p3, 0xffffffffL

    const/16 v1, 0x20

    iget-object v2, p0, Llyiahf/vczjk/wj;->OooO00o:Llyiahf/vczjk/wk;

    if-eqz p2, :cond_1

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/wj;->OooO0O0:Z

    iget-object p2, v2, Llyiahf/vczjk/wk;->OooO00o:Llyiahf/vczjk/qs5;

    int-to-long v5, v3

    shl-long v1, v5, v1

    int-to-long v5, v4

    and-long/2addr p3, v5

    or-long/2addr p3, v1

    new-instance v1, Llyiahf/vczjk/b24;

    invoke-direct {v1, p3, p4}, Llyiahf/vczjk/b24;-><init>(J)V

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    iget-boolean p2, p0, Llyiahf/vczjk/wj;->OooO0O0:Z

    if-nez p2, :cond_2

    iget-object p2, v2, Llyiahf/vczjk/wk;->OooO00o:Llyiahf/vczjk/qs5;

    int-to-long v5, v3

    shl-long v1, v5, v1

    int-to-long v5, v4

    and-long/2addr p3, v5

    or-long/2addr p3, v1

    new-instance v1, Llyiahf/vczjk/b24;

    invoke-direct {v1, p3, p4}, Llyiahf/vczjk/b24;-><init>(J)V

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_2
    :goto_1
    new-instance p2, Llyiahf/vczjk/vj;

    invoke-direct {p2, v0}, Llyiahf/vczjk/vj;-><init>(Ljava/util/ArrayList;)V

    sget-object p3, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v3, v4, p3, p2}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v0

    const/4 v1, 0x1

    if-gt v1, v0, :cond_2

    :goto_0
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result v2

    if-le v2, p1, :cond_1

    move p1, v2

    :cond_1
    if-eq v1, v0, :cond_2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return p1
.end method

.method public final OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v0

    const/4 v1, 0x1

    if-gt v1, v0, :cond_2

    :goto_0
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result v2

    if-le v2, p1, :cond_1

    move p1, v2

    :cond_1
    if-eq v1, v0, :cond_2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return p1
.end method

.method public final OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 3

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    :cond_0
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ef5;

    invoke-interface {p1, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    invoke-static {p2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v0

    const/4 v1, 0x1

    if-gt v1, v0, :cond_2

    :goto_0
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v2, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result v2

    if-le v2, p1, :cond_1

    move p1, v2

    :cond_1
    if-eq v1, v0, :cond_2

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return p1
.end method
