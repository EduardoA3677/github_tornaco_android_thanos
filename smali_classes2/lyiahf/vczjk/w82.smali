.class public final Llyiahf/vczjk/w82;
.super Llyiahf/vczjk/o00oOoo;
.source "SourceFile"


# instance fields
.field public final OooOoO:Llyiahf/vczjk/u72;

.field public final OooOoOO:Llyiahf/vczjk/md7;

.field public final OooOoo0:Llyiahf/vczjk/x72;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u72;Llyiahf/vczjk/md7;I)V
    .locals 10

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v2, v0, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    sget-object v4, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-virtual {p2}, Llyiahf/vczjk/md7;->OooOoO0()I

    move-result v1

    iget-object v3, p1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/rt5;

    invoke-static {v3, v1}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {p2}, Llyiahf/vczjk/md7;->OooOoo()Llyiahf/vczjk/ld7;

    move-result-object v1

    const-string v3, "getVariance(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-eqz v1, :cond_2

    const/4 v3, 0x1

    if-eq v1, v3, :cond_1

    const/4 v3, 0x2

    if-ne v1, v3, :cond_0

    sget-object v1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    :goto_0
    move-object v6, v1

    goto :goto_1

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    sget-object v1, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    goto :goto_0

    :cond_2
    sget-object v1, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    goto :goto_0

    :goto_1
    invoke-virtual {p2}, Llyiahf/vczjk/md7;->OooOoO()Z

    move-result v7

    sget-object v9, Llyiahf/vczjk/sp3;->OooOo00:Llyiahf/vczjk/sp3;

    iget-object v1, p1, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/v02;

    move-object v1, p0

    move v8, p3

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/o00oOoo;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/cda;ZILlyiahf/vczjk/sp3;)V

    iput-object p1, v1, Llyiahf/vczjk/w82;->OooOoO:Llyiahf/vczjk/u72;

    iput-object p2, v1, Llyiahf/vczjk/w82;->OooOoOO:Llyiahf/vczjk/md7;

    new-instance p1, Llyiahf/vczjk/x72;

    iget-object p2, v0, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p3, Llyiahf/vczjk/o0oOOo;

    const/16 v0, 0xb

    invoke-direct {p3, p0, v0}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/x72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p1, v1, Llyiahf/vczjk/w82;->OooOoo0:Llyiahf/vczjk/x72;

    return-void
.end method


# virtual methods
.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w82;->OooOoo0:Llyiahf/vczjk/x72;

    return-object v0
.end method

.method public final o0000O0O()Ljava/util/List;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/w82;->OooOoO:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h87;

    iget-object v2, p0, Llyiahf/vczjk/w82;->OooOoOO:Llyiahf/vczjk/md7;

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/md7;->OooOoo0()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    const/16 v4, 0xa

    if-nez v3, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/md7;->OooOoOO()Ljava/util/List;

    move-result-object v2

    const-string v3, "getUpperBoundIdList(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Integer;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    move-result v5

    invoke-virtual {v1, v5}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOOO()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_2
    new-instance v1, Ljava/util/ArrayList;

    invoke-static {v3, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hd7;

    iget-object v4, v0, Llyiahf/vczjk/u72;->OooO0oo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/t3a;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_3
    return-object v1
.end method
