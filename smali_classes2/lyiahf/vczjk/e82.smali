.class public final Llyiahf/vczjk/e82;
.super Llyiahf/vczjk/r82;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/o45;

.field public final OooO0oO:Llyiahf/vczjk/al4;

.field public final OooO0oo:Llyiahf/vczjk/o45;

.field public final synthetic OooOO0:Llyiahf/vczjk/h82;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h82;Llyiahf/vczjk/al4;)V
    .locals 7

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v2, p1, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v0, p1, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v0}, Llyiahf/vczjk/zb7;->ooOO()Ljava/util/List;

    move-result-object v3

    const-string v1, "getFunctionList(...)"

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/zb7;->o0ooOoO()Ljava/util/List;

    move-result-object v4

    const-string v1, "getPropertyList(...)"

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/zb7;->oo0o0Oo()Ljava/util/List;

    move-result-object v5

    const-string v1, "getTypeAliasList(...)"

    invoke-static {v5, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/zb7;->o0ooOOo()Ljava/util/List;

    move-result-object v0

    const-string v1, "getNestedClassNameList(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rt5;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v0, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v1, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    invoke-static {p1, v6}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    new-instance v6, Llyiahf/vczjk/b82;

    const/4 p1, 0x0

    invoke-direct {v6, p1, v1}, Llyiahf/vczjk/b82;-><init>(ILjava/util/ArrayList;)V

    move-object v1, p0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/r82;-><init>(Llyiahf/vczjk/u72;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/le3;)V

    iput-object p2, v1, Llyiahf/vczjk/e82;->OooO0oO:Llyiahf/vczjk/al4;

    iget-object p1, v2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p2, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v0, Llyiahf/vczjk/c82;

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/c82;-><init>(Llyiahf/vczjk/e82;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/o45;

    invoke-direct {v2, p2, v0}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v2, v1, Llyiahf/vczjk/e82;->OooO0oo:Llyiahf/vczjk/o45;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/c82;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/c82;-><init>(Llyiahf/vczjk/e82;I)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/o45;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v0, v1, Llyiahf/vczjk/e82;->OooO:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e82;->OooOOoo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v0, v0, Llyiahf/vczjk/h82;->OooOoo0:Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r60;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/r82;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e82;->OooOOoo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/r82;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e82;->OooO0oo:Llyiahf/vczjk/o45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/e82;->OooOOoo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/r82;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oo(Ljava/util/ArrayList;Llyiahf/vczjk/oe3;)V
    .locals 4

    iget-object p2, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object p2, p2, Llyiahf/vczjk/h82;->OooOoo0:Llyiahf/vczjk/ld9;

    if-eqz p2, :cond_1

    iget-object v0, p2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qt5;

    const-string v3, "name"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, p2, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/r60;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/by0;

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :cond_2
    if-nez v1, :cond_3

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_3
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    return-void
.end method

.method public final OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 7

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooO:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/h16;->OooOOOO:Llyiahf/vczjk/h16;

    invoke-interface {v1, p2, v2}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s72;

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooOOO:Llyiahf/vczjk/n1;

    iget-object v2, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    invoke-interface {v1, p2, v2}, Llyiahf/vczjk/n1;->Oooo0oO(Llyiahf/vczjk/qt5;Llyiahf/vczjk/by0;)Ljava/util/Collection;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOo0:Llyiahf/vczjk/u06;

    check-cast v0, Llyiahf/vczjk/v06;

    iget-object v1, v0, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    new-instance v6, Llyiahf/vczjk/d82;

    const/4 v0, 0x0

    invoke-direct {v6, p1, v0}, Llyiahf/vczjk/d82;-><init>(Ljava/util/AbstractCollection;I)V

    iget-object v5, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    move-object v2, p2

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/ng6;->OooO0oo(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/c6a;)V

    return-void
.end method

.method public final OooOO0O(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 7

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooO:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/h16;->OooOOOO:Llyiahf/vczjk/h16;

    invoke-interface {v1, p2, v2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    goto :goto_0

    :cond_0
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iget-object v0, p0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOo0:Llyiahf/vczjk/u06;

    check-cast v0, Llyiahf/vczjk/v06;

    iget-object v1, v0, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    new-instance v6, Llyiahf/vczjk/d82;

    const/4 v0, 0x0

    invoke-direct {v6, p1, v0}, Llyiahf/vczjk/d82;-><init>(Ljava/util/AbstractCollection;I)V

    iget-object v5, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    move-object v2, p2

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/ng6;->OooO0oo(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/c6a;)V

    return-void
.end method

.method public final OooOO0o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v0, v0, Llyiahf/vczjk/h82;->OooOo00:Llyiahf/vczjk/hy0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO()Ljava/util/Set;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v0, v0, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    invoke-virtual {v0}, Llyiahf/vczjk/o0O00000;->OooO()Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/jg5;->OooO0OO()Ljava/util/Set;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    if-nez v2, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-static {v2, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_1
    return-object v1
.end method

.method public final OooOOOO()Ljava/util/Set;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v1, v0, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    invoke-virtual {v1}, Llyiahf/vczjk/o0O00000;->OooO()Ljava/util/List;

    move-result-object v1

    new-instance v2, Ljava/util/LinkedHashSet;

    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/uk4;

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v3

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v3, v2}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s72;

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooOOO:Llyiahf/vczjk/n1;

    invoke-interface {v1, v0}, Llyiahf/vczjk/n1;->Oooo(Llyiahf/vczjk/by0;)Ljava/util/Collection;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    return-object v2
.end method

.method public final OooOOOo()Ljava/util/Set;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    iget-object v0, v0, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    invoke-virtual {v0}, Llyiahf/vczjk/o0O00000;->OooO()Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    invoke-static {v2, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final OooOOo(Llyiahf/vczjk/u82;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooOOOO:Llyiahf/vczjk/cx6;

    iget-object v1, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    invoke-interface {v0, v1, p1}, Llyiahf/vczjk/cx6;->OooO0o(Llyiahf/vczjk/by0;Llyiahf/vczjk/u82;)Z

    move-result p1

    return p1
.end method

.method public final OooOOoo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "location"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO:Llyiahf/vczjk/sp3;

    const-string p2, "<this>"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "scopeOwner"

    iget-object p2, p0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method
