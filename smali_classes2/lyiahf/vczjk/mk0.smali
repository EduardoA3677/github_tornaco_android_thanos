.class public abstract Llyiahf/vczjk/mk0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/Object;

.field public static final OooO0O0:Ljava/util/LinkedHashMap;

.field public static final OooO0OO:Ljava/util/Set;

.field public static final OooO0Oo:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    sget-object v0, Llyiahf/vczjk/w09;->OooOO0:Llyiahf/vczjk/ic3;

    const-string v1, "name"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ic3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/ic3;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/x09;->OooO0Oo:Llyiahf/vczjk/qt5;

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const-string v1, "ordinal"

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ic3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/ic3;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOoo:Llyiahf/vczjk/hc3;

    const-string v1, "size"

    invoke-static {v1, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->Oooo00O:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v6

    move-object v7, v6

    new-instance v6, Llyiahf/vczjk/xn6;

    invoke-direct {v6, v2, v7}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v2, Llyiahf/vczjk/w09;->OooO0o0:Llyiahf/vczjk/ic3;

    const-string v7, "length"

    invoke-static {v7}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    invoke-virtual {v2, v8}, Llyiahf/vczjk/ic3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/ic3;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v2

    invoke-static {v7}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    move-object v9, v7

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v2, v8}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const-string v2, "keys"

    invoke-static {v2, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v2

    const-string v8, "keySet"

    invoke-static {v8}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v8

    move-object v10, v8

    new-instance v8, Llyiahf/vczjk/xn6;

    invoke-direct {v8, v2, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const-string v2, "values"

    invoke-static {v2, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v10

    invoke-static {v2}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    move-object v11, v9

    new-instance v9, Llyiahf/vczjk/xn6;

    invoke-direct {v9, v10, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const-string v2, "entries"

    invoke-static {v2, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v0

    const-string v2, "entrySet"

    invoke-static {v2}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    new-instance v10, Llyiahf/vczjk/xn6;

    invoke-direct {v10, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->OoooOoo:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v11}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    move-object v12, v11

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->Ooooo00:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v12}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v2

    move-object v13, v12

    new-instance v12, Llyiahf/vczjk/xn6;

    invoke-direct {v12, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/w09;->Ooooo0o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/m6a;->OooOOO(Ljava/lang/String;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v13}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    new-instance v13, Llyiahf/vczjk/xn6;

    invoke-direct {v13, v0, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    filled-new-array/range {v3 .. v13}, [Llyiahf/vczjk/xn6;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o0ooOO0([Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/mk0;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    new-instance v4, Llyiahf/vczjk/xn6;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/hc3;

    iget-object v5, v5, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v5}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-direct {v4, v5, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xn6;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/qt5;

    invoke-virtual {v0, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_1

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    check-cast v5, Ljava/util/List;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qt5;

    invoke-interface {v5, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-interface {v0}, Ljava/util/Map;->size()I

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v3}, Llyiahf/vczjk/d21;->Ooooooo(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v3

    invoke-interface {v1, v4, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    :cond_3
    sput-object v1, Llyiahf/vczjk/mk0;->OooO0O0:Ljava/util/LinkedHashMap;

    sget-object v0, Llyiahf/vczjk/mk0;->OooO00o:Ljava/lang/Object;

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    sget-object v4, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/hc3;

    invoke-virtual {v4}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v4

    iget-object v4, v4, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {v4}, Llyiahf/vczjk/w64;->OooO0o(Llyiahf/vczjk/ic3;)Llyiahf/vczjk/hy0;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v4

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qt5;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v3

    invoke-interface {v1, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_4
    sget-object v0, Llyiahf/vczjk/mk0;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/mk0;->OooO0OO:Ljava/util/Set;

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/hc3;

    iget-object v2, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_5
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/mk0;->OooO0Oo:Ljava/util/Set;

    return-void
.end method
