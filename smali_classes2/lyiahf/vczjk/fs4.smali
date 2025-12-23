.class public final Llyiahf/vczjk/fs4;
.super Llyiahf/vczjk/gs4;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOOo:I


# instance fields
.field public final OooOOO:Llyiahf/vczjk/cm7;

.field public final OooOOOO:Llyiahf/vczjk/nr4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/cm7;Llyiahf/vczjk/nr4;)V
    .locals 1

    const-string v0, "jClass"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/ds4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rr4;)V

    iput-object p2, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    iput-object p3, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    return-void
.end method

.method public static OooOo0O(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/sa7;
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/eo0;->getKind()I

    move-result v0

    const/4 v1, 0x2

    if-eq v0, v1, :cond_0

    return-object p0

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/eo0;->OooOOO0()Ljava/util/Collection;

    move-result-object p0

    const-string v0, "getOverriddenDescriptors(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Ljava/lang/Iterable;

    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p0, v1}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sa7;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v1}, Llyiahf/vczjk/fs4;->OooOo0O(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/sa7;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/d21;->Ooooooo(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/sa7;

    return-object p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
    .locals 2

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c12;

    invoke-interface {p1}, Llyiahf/vczjk/c12;->OooO00o()Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000OOO(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    invoke-static {p2}, Llyiahf/vczjk/wr6;->OooOOO(Llyiahf/vczjk/by0;)Llyiahf/vczjk/fs4;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    :cond_1
    check-cast v0, Ljava/util/Collection;

    invoke-interface {p1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    iget-object v0, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    iget-object v0, v0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isEnum()Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/x09;->OooO0OO:Llyiahf/vczjk/qt5;

    sget-object v1, Llyiahf/vczjk/x09;->OooO00o:Llyiahf/vczjk/qt5;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-interface {p1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v1, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v1, Llyiahf/vczjk/up3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "thisDescriptor"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "c"

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1, p2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "location"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object p1
.end method

.method public final OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 2

    const-string p1, "name"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v0, Llyiahf/vczjk/up3;

    iget-object v1, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "thisDescriptor"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "c"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public final OooOO0O()Llyiahf/vczjk/c12;
    .locals 3

    new-instance v0, Llyiahf/vczjk/yx0;

    sget-object v1, Llyiahf/vczjk/g13;->OooOoO:Llyiahf/vczjk/g13;

    iget-object v2, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/yx0;-><init>(Llyiahf/vczjk/cm7;Llyiahf/vczjk/oe3;)V

    return-object v0
.end method

.method public final OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 10

    const-string v1, "name"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    new-instance v2, Llyiahf/vczjk/oo000o;

    const/16 v3, 0x10

    invoke-direct {v2, p2, v3}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    iget-object v6, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    invoke-static {v6}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/pp3;->OooOOo:Llyiahf/vczjk/pp3;

    new-instance v5, Llyiahf/vczjk/es4;

    invoke-direct {v5, v6, v1, v2}, Llyiahf/vczjk/es4;-><init>(Llyiahf/vczjk/nr4;Ljava/util/Set;Llyiahf/vczjk/oe3;)V

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/jp8;->OooOo00(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/so8;)Ljava/lang/Object;

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v2

    iget-object v7, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    if-nez v2, :cond_0

    iget-object v2, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v3, v2, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v5, v3, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v3, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    iget-object v4, v2, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object v2, p1

    move-object v0, p2

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/jp8;->OoooO0(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/AbstractCollection;Llyiahf/vczjk/nr4;Llyiahf/vczjk/qp3;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    goto :goto_2

    :cond_0
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/sa7;

    invoke-static {v4}, Llyiahf/vczjk/fs4;->OooOo0O(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/sa7;

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_1

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    check-cast v5, Ljava/util/List;

    invoke-interface {v5, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map$Entry;

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Ljava/util/Collection;

    iget-object v0, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v3, v0, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v5, v3, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v3, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    iget-object v4, v0, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object v2, p1

    move-object v0, p2

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/jp8;->OoooO0(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/AbstractCollection;Llyiahf/vczjk/nr4;Llyiahf/vczjk/qp3;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object v1

    invoke-static {v1, v8}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_1

    :cond_3
    invoke-virtual {p1, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :goto_2
    iget-object v1, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    iget-object v1, v1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->isEnum()Z

    move-result v1

    if-eqz v1, :cond_4

    sget-object v1, Llyiahf/vczjk/x09;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-static {v6}, Llyiahf/vczjk/dn8;->Oooo(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ua7;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    :cond_4
    return-void
.end method

.method public final OooOOO0(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;)V
    .locals 8

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    invoke-static {v0}, Llyiahf/vczjk/wr6;->OooOOO(Llyiahf/vczjk/by0;)Llyiahf/vczjk/fs4;

    move-result-object v1

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/h16;->OooOOo0:Llyiahf/vczjk/h16;

    invoke-virtual {v1, p2, v2}, Llyiahf/vczjk/ds4;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v1

    :goto_0
    move-object v3, v1

    check-cast v3, Ljava/util/Collection;

    iget-object v1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v2, v1, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v7, v2, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v5, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    iget-object v6, v1, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object v4, p1

    move-object v2, p2

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/jp8;->OoooO0(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/AbstractCollection;Llyiahf/vczjk/nr4;Llyiahf/vczjk/qp3;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object p1

    invoke-interface {v4, p1}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    iget-object p1, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    iget-object p1, p1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->isEnum()Z

    move-result p1

    if-eqz p1, :cond_2

    sget-object p1, Llyiahf/vczjk/x09;->OooO0OO:Llyiahf/vczjk/qt5;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/dn8;->OoooO00(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ho8;

    move-result-object p1

    invoke-interface {v4, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    return-void

    :cond_1
    sget-object p1, Llyiahf/vczjk/x09;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-static {v0}, Llyiahf/vczjk/dn8;->OoooO0(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ho8;

    move-result-object p1

    invoke-interface {v4, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    :cond_2
    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/e72;)Ljava/util/Set;
    .locals 5

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c12;

    invoke-interface {p1}, Llyiahf/vczjk/c12;->OooO0o0()Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000OOO(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/g13;->OooOoOO:Llyiahf/vczjk/g13;

    iget-object v1, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/pp3;->OooOOo:Llyiahf/vczjk/pp3;

    new-instance v4, Llyiahf/vczjk/es4;

    invoke-direct {v4, v1, p1, v0}, Llyiahf/vczjk/es4;-><init>(Llyiahf/vczjk/nr4;Ljava/util/Set;Llyiahf/vczjk/oe3;)V

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/jp8;->OooOo00(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/so8;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/fs4;->OooOOO:Llyiahf/vczjk/cm7;

    iget-object v0, v0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isEnum()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/x09;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-interface {p1, v0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    :cond_0
    return-object p1
.end method

.method public final OooOOo0()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fs4;->OooOOOO:Llyiahf/vczjk/nr4;

    return-object v0
.end method
