.class public final Llyiahf/vczjk/t3a;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/u72;

.field public final OooO0O0:Llyiahf/vczjk/t3a;

.field public final OooO0OO:Ljava/lang/String;

.field public final OooO0Oo:Ljava/lang/String;

.field public final OooO0o:Llyiahf/vczjk/r60;

.field public final OooO0o0:Llyiahf/vczjk/r60;

.field public final OooO0oO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u72;Llyiahf/vczjk/t3a;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "debugName"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iput-object p2, p0, Llyiahf/vczjk/t3a;->OooO0O0:Llyiahf/vczjk/t3a;

    iput-object p4, p0, Llyiahf/vczjk/t3a;->OooO0OO:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/t3a;->OooO0Oo:Ljava/lang/String;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p2, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p4, Llyiahf/vczjk/r3a;

    const/4 p5, 0x0

    invoke-direct {p4, p0, p5}, Llyiahf/vczjk/r3a;-><init>(Llyiahf/vczjk/t3a;I)V

    invoke-virtual {p2, p4}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/t3a;->OooO0o0:Llyiahf/vczjk/r60;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/r3a;

    const/4 p4, 0x1

    invoke-direct {p2, p0, p4}, Llyiahf/vczjk/r3a;-><init>(Llyiahf/vczjk/t3a;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/t3a;->OooO0o:Llyiahf/vczjk/r60;

    invoke-interface {p3}, Ljava/util/List;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    const/4 p3, 0x0

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result p4

    if-eqz p4, :cond_1

    add-int/lit8 p4, p3, 0x1

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p5

    check-cast p5, Llyiahf/vczjk/md7;

    invoke-virtual {p5}, Llyiahf/vczjk/md7;->OooOo()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/w82;

    iget-object v2, p0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    invoke-direct {v1, v2, p5, p3}, Llyiahf/vczjk/w82;-><init>(Llyiahf/vczjk/u72;Llyiahf/vczjk/md7;I)V

    invoke-interface {p1, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move p3, p4

    goto :goto_0

    :cond_1
    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/t3a;->OooO0oO:Ljava/lang/Object;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;
    .locals 7

    invoke-static {p0}, Llyiahf/vczjk/fu6;->OooOO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v1

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOo0O(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object v2

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOOOO(Llyiahf/vczjk/uk4;)Ljava/util/List;

    move-result-object v3

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOo0o(Llyiahf/vczjk/uk4;)Ljava/util/List;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/d21;->ooOO(Ljava/util/List;)Ljava/util/List;

    move-result-object v4

    move-object v5, v4

    new-instance v4, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v5, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_0

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/z4a;

    invoke-virtual {v6}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v6

    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    const/4 v6, 0x1

    move-object v5, p1

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/ye5;->OooOO0o(Llyiahf/vczjk/hk4;Llyiahf/vczjk/ko;Llyiahf/vczjk/uk4;Ljava/util/List;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result p0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0o(Ljava/util/List;Llyiahf/vczjk/ko;Llyiahf/vczjk/n3a;Llyiahf/vczjk/v02;)Llyiahf/vczjk/d3a;
    .locals 1

    new-instance p2, Ljava/util/ArrayList;

    const/16 p3, 0xa

    invoke-static {p0, p3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p3

    invoke-direct {p2, p3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p3

    if-eqz p3, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/q42;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p1}, Llyiahf/vczjk/ko;->isEmpty()Z

    move-result p3

    if-eqz p3, :cond_0

    sget-object p3, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p3, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    goto :goto_1

    :cond_0
    sget-object p3, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    new-instance v0, Llyiahf/vczjk/qo;

    invoke-direct {v0, p1}, Llyiahf/vczjk/qo;-><init>(Llyiahf/vczjk/ko;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/xo8;->OooO0o(Ljava/util/List;)Llyiahf/vczjk/d3a;

    move-result-object p3

    :goto_1
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    new-instance p0, Ljava/util/ArrayList;

    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Iterable;

    invoke-static {p2, p0}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_2

    :cond_2
    sget-object p1, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0}, Llyiahf/vczjk/xo8;->OooO0o(Ljava/util/List;)Llyiahf/vczjk/d3a;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/hd7;Llyiahf/vczjk/t3a;)Ljava/util/ArrayList;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/hd7;->Oooo00o()Ljava/util/List;

    move-result-object v0

    const-string v1, "getArgumentList(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p1, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h87;

    invoke-static {p0, v1}, Llyiahf/vczjk/eo6;->OooOo00(Llyiahf/vczjk/hd7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/t3a;->OooO0o0(Llyiahf/vczjk/hd7;Llyiahf/vczjk/t3a;)Ljava/util/ArrayList;

    move-result-object p0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-nez p0, :cond_1

    sget-object p0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_1
    invoke-static {p0, v0}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/t3a;Llyiahf/vczjk/hd7;I)Llyiahf/vczjk/by0;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rt5;

    invoke-static {v0, p2}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/r3a;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/r3a;-><init>(Llyiahf/vczjk/t3a;I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/iu6;->Oooo0OO:Llyiahf/vczjk/iu6;

    invoke-static {p1, v0}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/jy9;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/iy9;

    invoke-virtual {v1}, Llyiahf/vczjk/iy9;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/iy9;->next()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/s3a;->OooOOO:Llyiahf/vczjk/s3a;

    invoke-static {p2, p1}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/ag8;->Oooo00o(Llyiahf/vczjk/wf8;)I

    move-result p1

    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge v1, p1, :cond_1

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    iget-object p0, p0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object p0, p0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/s72;

    iget-object p0, p0, Llyiahf/vczjk/s72;->OooOO0o:Llyiahf/vczjk/ld9;

    invoke-virtual {p0, p2, v0}, Llyiahf/vczjk/ld9;->OoooO(Llyiahf/vczjk/hy0;Ljava/util/List;)Llyiahf/vczjk/by0;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final OooO0O0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/t3a;->OooO0oO:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO(I)Llyiahf/vczjk/t4a;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/t3a;->OooO0oO:Ljava/lang/Object;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t4a;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/t3a;->OooO0O0:Llyiahf/vczjk/t3a;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/t3a;->OooO0OO(I)Llyiahf/vczjk/t4a;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1

    :cond_1
    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;
    .locals 25

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    const-string v4, "proto"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooOO0()Z

    move-result v4

    iget-object v5, v0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    if-eqz v4, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0()I

    move-result v4

    iget-object v6, v5, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/rt5;

    invoke-static {v6, v4}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object v4

    iget-boolean v4, v4, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v4, :cond_1

    iget-object v4, v5, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s72;

    iget-object v4, v4, Llyiahf/vczjk/s72;->OooO0oO:Llyiahf/vczjk/qp3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Ooooo0o()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo()I

    move-result v4

    iget-object v6, v5, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/rt5;

    invoke-static {v6, v4}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object v4

    iget-boolean v4, v4, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v4, :cond_1

    iget-object v4, v5, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s72;

    iget-object v4, v4, Llyiahf/vczjk/s72;->OooO0oO:Llyiahf/vczjk/qp3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooOO0()Z

    move-result v4

    const-string v7, "getTypeConstructor(...)"

    if-eqz v4, :cond_2

    iget-object v4, v0, Llyiahf/vczjk/t3a;->OooO0o0:Llyiahf/vczjk/r60;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0()I

    move-result v8

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-virtual {v4, v8}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/gz0;

    if-nez v4, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0()I

    move-result v4

    invoke-static {v0, v1, v4}, Llyiahf/vczjk/t3a;->OooO0oo(Llyiahf/vczjk/t3a;Llyiahf/vczjk/hd7;I)Llyiahf/vczjk/by0;

    move-result-object v4

    goto/16 :goto_2

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OooooO0()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooO00()I

    move-result v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/t3a;->OooO0OO(I)Llyiahf/vczjk/t4a;

    move-result-object v4

    if-nez v4, :cond_8

    sget-object v4, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v4, Llyiahf/vczjk/tq2;->OooOoO0:Llyiahf/vczjk/tq2;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooO00()I

    move-result v8

    invoke-static {v8}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v8

    iget-object v9, v0, Llyiahf/vczjk/t3a;->OooO0Oo:Ljava/lang/String;

    filled-new-array {v8, v9}, [Ljava/lang/String;

    move-result-object v8

    invoke-static {v4, v8}, Llyiahf/vczjk/uq2;->OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;

    move-result-object v4

    goto/16 :goto_3

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OooooOO()Z

    move-result v4

    if-eqz v4, :cond_7

    iget-object v4, v5, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/rt5;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooO0()I

    move-result v8

    invoke-interface {v4, v8}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0}, Llyiahf/vczjk/t3a;->OooO0O0()Ljava/util/List;

    move-result-object v8

    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :cond_4
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_5

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/t4a;

    invoke-interface {v10}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v10

    invoke-virtual {v10}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v10

    invoke-static {v10, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_4

    goto :goto_1

    :cond_5
    const/4 v9, 0x0

    :goto_1
    move-object v8, v9

    check-cast v8, Llyiahf/vczjk/t4a;

    if-nez v8, :cond_6

    sget-object v8, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v8, Llyiahf/vczjk/tq2;->OooOoO:Llyiahf/vczjk/tq2;

    iget-object v9, v5, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/v02;

    invoke-virtual {v9}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v9

    filled-new-array {v4, v9}, [Ljava/lang/String;

    move-result-object v4

    invoke-static {v8, v4}, Llyiahf/vczjk/uq2;->OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;

    move-result-object v4

    goto :goto_3

    :cond_6
    move-object v4, v8

    goto :goto_2

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Ooooo0o()Z

    move-result v4

    if-eqz v4, :cond_9

    iget-object v4, v0, Llyiahf/vczjk/t3a;->OooO0o:Llyiahf/vczjk/r60;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo()I

    move-result v8

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-virtual {v4, v8}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/gz0;

    if-nez v4, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo()I

    move-result v4

    invoke-static {v0, v1, v4}, Llyiahf/vczjk/t3a;->OooO0oo(Llyiahf/vczjk/t3a;Llyiahf/vczjk/hd7;I)Llyiahf/vczjk/by0;

    move-result-object v4

    :cond_8
    :goto_2
    invoke-interface {v4}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v4

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_3

    :cond_9
    sget-object v4, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v4, Llyiahf/vczjk/tq2;->OooOoo0:Llyiahf/vczjk/tq2;

    new-array v8, v2, [Ljava/lang/String;

    invoke-static {v4, v8}, Llyiahf/vczjk/uq2;->OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;

    move-result-object v4

    :goto_3
    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/uq2;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v8

    if-eqz v8, :cond_a

    sget-object v1, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v1, Llyiahf/vczjk/tq2;->Oooo00O:Llyiahf/vczjk/tq2;

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v2

    check-cast v2, [Ljava/lang/String;

    invoke-static {v1, v5, v4, v2}, Llyiahf/vczjk/uq2;->OooO0o0(Llyiahf/vczjk/tq2;Ljava/util/List;Llyiahf/vczjk/n3a;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v1

    return-object v1

    :cond_a
    new-instance v8, Llyiahf/vczjk/x72;

    iget-object v9, v5, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/s72;

    iget-object v9, v9, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v10, Llyiahf/vczjk/ema;

    invoke-direct {v10, v3, v0, v1}, Llyiahf/vczjk/ema;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-direct {v8, v9, v10}, Llyiahf/vczjk/x72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iget-object v9, v5, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/s72;

    iget-object v10, v9, Llyiahf/vczjk/s72;->OooOOo:Ljava/util/List;

    iget-object v11, v5, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/v02;

    invoke-static {v10, v8, v4, v11}, Llyiahf/vczjk/t3a;->OooO0o(Ljava/util/List;Llyiahf/vczjk/ko;Llyiahf/vczjk/n3a;Llyiahf/vczjk/v02;)Llyiahf/vczjk/d3a;

    move-result-object v10

    invoke-static {v1, v0}, Llyiahf/vczjk/t3a;->OooO0o0(Llyiahf/vczjk/hd7;Llyiahf/vczjk/t3a;)Ljava/util/ArrayList;

    move-result-object v12

    new-instance v13, Ljava/util/ArrayList;

    const/16 v14, 0xa

    invoke-static {v12, v14}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v15

    invoke-direct {v13, v15}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v12}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v12

    move v15, v2

    :goto_4
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    move-result v16

    iget-object v2, v5, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/h87;

    if-eqz v16, :cond_15

    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v16

    add-int/lit8 v17, v15, 0x1

    if-ltz v15, :cond_14

    check-cast v16, Llyiahf/vczjk/fd7;

    const/16 v18, 0x0

    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    const-string v14, "getParameters(...)"

    invoke-static {v6, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v15, v6}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/t4a;

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooO()Llyiahf/vczjk/ed7;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/ed7;->OooOOOo:Llyiahf/vczjk/ed7;

    if-ne v14, v15, :cond_c

    if-nez v6, :cond_b

    new-instance v2, Llyiahf/vczjk/d19;

    iget-object v6, v9, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-interface {v6}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v6

    invoke-direct {v2, v6}, Llyiahf/vczjk/d19;-><init>(Llyiahf/vczjk/hk4;)V

    goto/16 :goto_7

    :cond_b
    new-instance v2, Llyiahf/vczjk/f19;

    invoke-direct {v2, v6}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    goto/16 :goto_7

    :cond_c
    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooO()Llyiahf/vczjk/ed7;

    move-result-object v6

    const-string v14, "getProjection(...)"

    invoke-static {v6, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v14

    if-eqz v14, :cond_10

    if-eq v14, v3, :cond_f

    const/4 v15, 0x2

    if-eq v14, v15, :cond_e

    const/4 v1, 0x3

    if-eq v14, v1, :cond_d

    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :cond_d
    new-instance v1, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Only IN, OUT and INV are supported. Actual argument: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_e
    sget-object v6, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    goto :goto_5

    :cond_f
    sget-object v6, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    goto :goto_5

    :cond_10
    sget-object v6, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    :goto_5
    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooOOO0()Z

    move-result v14

    if-eqz v14, :cond_11

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooOO0()Llyiahf/vczjk/hd7;

    move-result-object v2

    goto :goto_6

    :cond_11
    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooOOO()Z

    move-result v14

    if-eqz v14, :cond_12

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fd7;->OooOO0O()I

    move-result v14

    invoke-virtual {v2, v14}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v2

    goto :goto_6

    :cond_12
    move-object/from16 v2, v18

    :goto_6
    if-nez v2, :cond_13

    new-instance v2, Llyiahf/vczjk/f19;

    sget-object v6, Llyiahf/vczjk/tq2;->Oooo0o0:Llyiahf/vczjk/tq2;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v14

    filled-new-array {v14}, [Ljava/lang/String;

    move-result-object v14

    invoke-static {v6, v14}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v6

    invoke-direct {v2, v6}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;)V

    goto :goto_7

    :cond_13
    new-instance v14, Llyiahf/vczjk/f19;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/t3a;->OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;

    move-result-object v2

    invoke-direct {v14, v2, v6}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    move-object v2, v14

    :goto_7
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move/from16 v15, v17

    const/4 v2, 0x0

    const/16 v14, 0xa

    goto/16 :goto_4

    :cond_14
    const/16 v18, 0x0

    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v18

    :cond_15
    const/16 v18, 0x0

    invoke-static {v13}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v5

    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v6

    if-eqz p2, :cond_1a

    instance-of v12, v6, Llyiahf/vczjk/a3a;

    if-eqz v12, :cond_1a

    check-cast v6, Llyiahf/vczjk/a3a;

    const-string v7, "<this>"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v7, Llyiahf/vczjk/tp3;

    const/16 v10, 0x1a

    invoke-direct {v7, v10}, Llyiahf/vczjk/tp3;-><init>(I)V

    move-object v10, v6

    check-cast v10, Llyiahf/vczjk/v82;

    iget-object v10, v10, Llyiahf/vczjk/v82;->OooOo0o:Llyiahf/vczjk/o0O0o;

    invoke-virtual {v10}, Llyiahf/vczjk/o0O0o;->OooO0OO()Ljava/util/List;

    move-result-object v10

    new-instance v12, Ljava/util/ArrayList;

    const/16 v13, 0xa

    invoke-static {v10, v13}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-direct {v12, v13}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :goto_8
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_16

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/t4a;

    invoke-interface {v13}, Llyiahf/vczjk/t4a;->OooO00o()Llyiahf/vczjk/t4a;

    move-result-object v13

    invoke-virtual {v12, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_8

    :cond_16
    invoke-static {v12, v5}, Llyiahf/vczjk/d21;->o0000Oo(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v10

    new-instance v12, Llyiahf/vczjk/pb7;

    move-object/from16 v13, v18

    invoke-direct {v12, v13, v6, v5, v10}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/pb7;Llyiahf/vczjk/a3a;Ljava/util/List;Ljava/util/Map;)V

    sget-object v5, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    const-string v6, "attributes"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v23, 0x0

    const/16 v24, 0x1

    const/16 v22, 0x0

    move-object/from16 v21, v5

    move-object/from16 v19, v7

    move-object/from16 v20, v12

    invoke-virtual/range {v19 .. v24}, Llyiahf/vczjk/tp3;->OooOOOO(Llyiahf/vczjk/pb7;Llyiahf/vczjk/d3a;ZIZ)Llyiahf/vczjk/dp8;

    move-result-object v5

    iget-object v6, v9, Llyiahf/vczjk/s72;->OooOOo:Ljava/util/List;

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v7

    invoke-static {v8, v7}, Llyiahf/vczjk/d21;->o000000o(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    move-result-object v7

    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_17

    sget-object v7, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    goto :goto_9

    :cond_17
    new-instance v8, Llyiahf/vczjk/po;

    const/4 v9, 0x0

    invoke-direct {v8, v9, v7}, Llyiahf/vczjk/po;-><init>(ILjava/util/List;)V

    move-object v7, v8

    :goto_9
    invoke-static {v6, v7, v4, v11}, Llyiahf/vczjk/t3a;->OooO0o(Ljava/util/List;Llyiahf/vczjk/ko;Llyiahf/vczjk/n3a;Llyiahf/vczjk/v02;)Llyiahf/vczjk/d3a;

    move-result-object v4

    invoke-static {v5}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v6

    if-nez v6, :cond_19

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0o()Z

    move-result v6

    if-eqz v6, :cond_18

    goto :goto_a

    :cond_18
    const/4 v3, 0x0

    :cond_19
    :goto_a
    invoke-virtual {v5, v3}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v3

    invoke-virtual {v3, v4}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object v3

    goto/16 :goto_12

    :cond_1a
    move-object/from16 v13, v18

    sget-object v6, Llyiahf/vczjk/c23;->OooO00o:Llyiahf/vczjk/z13;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->getFlags()I

    move-result v8

    invoke-virtual {v6, v8}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    if-eqz v6, :cond_27

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0o()Z

    move-result v6

    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v8

    invoke-interface {v8}, Ljava/util/List;->size()I

    move-result v8

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v9

    sub-int/2addr v8, v9

    if-eqz v8, :cond_1d

    if-eq v8, v3, :cond_1c

    :cond_1b
    :goto_b
    move-object v3, v13

    goto/16 :goto_11

    :cond_1c
    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v8

    sub-int/2addr v8, v3

    if-ltz v8, :cond_1b

    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v3

    invoke-virtual {v3, v8}, Llyiahf/vczjk/hk4;->OooOo0o(I)Llyiahf/vczjk/by0;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-static {v3, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5, v10, v3, v6}, Llyiahf/vczjk/so8;->Oooo0oO(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v3

    goto/16 :goto_11

    :cond_1d
    invoke-static {v5, v10, v4, v6}, Llyiahf/vczjk/so8;->Oooo0oO(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v7

    if-eqz v7, :cond_1e

    invoke-static {v7}, Llyiahf/vczjk/ye5;->OooOOo0(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/bg3;

    move-result-object v7

    goto :goto_c

    :cond_1e
    move-object v7, v13

    :goto_c
    sget-object v8, Llyiahf/vczjk/xf3;->OooO0OO:Llyiahf/vczjk/xf3;

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_1f

    goto :goto_b

    :cond_1f
    invoke-static {v6}, Llyiahf/vczjk/ye5;->OooOo0o(Llyiahf/vczjk/uk4;)Ljava/util/List;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/z4a;

    if-eqz v7, :cond_1b

    invoke-virtual {v7}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v7

    if-nez v7, :cond_20

    goto :goto_b

    :cond_20
    invoke-virtual {v7}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v8

    invoke-interface {v8}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v8

    if-eqz v8, :cond_21

    invoke-static {v8}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v8

    goto :goto_d

    :cond_21
    move-object v8, v13

    :goto_d
    invoke-virtual {v7}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v9

    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v9

    if-ne v9, v3, :cond_26

    sget-object v3, Llyiahf/vczjk/x09;->OooO0oO:Llyiahf/vczjk/hc3;

    invoke-static {v8, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_22

    sget-object v3, Llyiahf/vczjk/w3a;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v8, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_22

    goto :goto_10

    :cond_22
    invoke-virtual {v7}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/z4a;

    invoke-virtual {v3}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v3

    const-string v7, "getType(...)"

    invoke-static {v3, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v7, v11, Llyiahf/vczjk/co0;

    if-eqz v7, :cond_23

    check-cast v11, Llyiahf/vczjk/co0;

    goto :goto_e

    :cond_23
    move-object v11, v13

    :goto_e
    if-eqz v11, :cond_24

    invoke-static {v11}, Llyiahf/vczjk/p72;->OooO0OO(Llyiahf/vczjk/x02;)Llyiahf/vczjk/hc3;

    move-result-object v7

    goto :goto_f

    :cond_24
    move-object v7, v13

    :goto_f
    sget-object v8, Llyiahf/vczjk/cb9;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_25

    invoke-static {v6, v3}, Llyiahf/vczjk/t3a;->OooO00o(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v3

    goto :goto_11

    :cond_25
    invoke-static {v6, v3}, Llyiahf/vczjk/t3a;->OooO00o(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v3

    goto :goto_11

    :cond_26
    :goto_10
    move-object v3, v6

    :goto_11
    if-nez v3, :cond_2a

    sget-object v3, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v3, Llyiahf/vczjk/tq2;->OooOoOO:Llyiahf/vczjk/tq2;

    const/4 v9, 0x0

    new-array v6, v9, [Ljava/lang/String;

    invoke-static {v3, v5, v4, v6}, Llyiahf/vczjk/uq2;->OooO0o0(Llyiahf/vczjk/tq2;Ljava/util/List;Llyiahf/vczjk/n3a;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v3

    goto :goto_12

    :cond_27
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo0o()Z

    move-result v6

    invoke-static {v5, v10, v4, v6}, Llyiahf/vczjk/so8;->Oooo0oO(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/c23;->OooO0O0:Llyiahf/vczjk/z13;

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->getFlags()I

    move-result v6

    invoke-virtual {v5, v6}, Llyiahf/vczjk/z13;->OooOO0o(I)Ljava/lang/Boolean;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    if-eqz v5, :cond_29

    invoke-static {v4, v3}, Llyiahf/vczjk/rp3;->OooOOo(Llyiahf/vczjk/iaa;Z)Llyiahf/vczjk/a52;

    move-result-object v3

    if-eqz v3, :cond_28

    goto :goto_12

    :cond_28
    new-instance v1, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "null DefinitelyNotNullType for \'"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v3, 0x27

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_29
    move-object v3, v4

    :cond_2a
    :goto_12
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooO0O()Z

    move-result v4

    if-eqz v4, :cond_2b

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OooOooo()Llyiahf/vczjk/hd7;

    move-result-object v6

    goto :goto_13

    :cond_2b
    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->OoooO()Z

    move-result v4

    if-eqz v4, :cond_2c

    invoke-virtual {v1}, Llyiahf/vczjk/hd7;->Oooo000()I

    move-result v1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v6

    goto :goto_13

    :cond_2c
    move-object v6, v13

    :goto_13
    if-eqz v6, :cond_2d

    const/4 v9, 0x0

    invoke-virtual {v0, v6, v9}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object v1

    invoke-static {v3, v1}, Llyiahf/vczjk/ll6;->OooOOo(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object v1

    return-object v1

    :cond_2d
    return-object v3
.end method

.method public final OooO0oO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/uk4;
    .locals 6

    const-string v0, "proto"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->OoooOOO()Z

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v2, v0, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rt5;

    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->Oooo0O0()I

    move-result v3

    invoke-interface {v2, v3}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object v3

    iget-object v4, v0, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h87;

    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->OoooOOo()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->Oooo0OO()Llyiahf/vczjk/hd7;

    move-result-object v4

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->OoooOo0()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/hd7;->Oooo0o0()I

    move-result v5

    invoke-virtual {v4, v5}, Llyiahf/vczjk/h87;->OooO0Oo(I)Llyiahf/vczjk/hd7;

    move-result-object v4

    goto :goto_0

    :cond_1
    const/4 v4, 0x0

    :goto_0
    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p0, v4, v1}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOO0:Llyiahf/vczjk/l23;

    invoke-interface {v0, p1, v2, v3, v1}, Llyiahf/vczjk/l23;->OooO0oo(Llyiahf/vczjk/hd7;Ljava/lang/String;Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1

    :cond_2
    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/t3a;->OooO0Oo(Llyiahf/vczjk/hd7;Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/t3a;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/t3a;->OooO0O0:Llyiahf/vczjk/t3a;

    if-nez v1, :cond_0

    const-string v1, ""

    goto :goto_0

    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, ". Child of "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/t3a;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
