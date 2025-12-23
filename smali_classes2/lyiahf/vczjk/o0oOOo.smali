.class public final Llyiahf/vczjk/o0oOOo;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o0oOOo;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0oOOo;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 26

    move-object/from16 v0, p0

    const/4 v1, 0x1

    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v3, 0x3

    sget-object v4, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    const/16 v5, 0xa

    const/4 v6, 0x0

    const/4 v7, 0x0

    iget-object v8, v0, Llyiahf/vczjk/o0oOOo;->OooOOO:Ljava/lang/Object;

    iget v9, v0, Llyiahf/vczjk/o0oOOo;->OooOOO0:I

    packed-switch v9, :pswitch_data_0

    check-cast v8, Llyiahf/vczjk/z88;

    iget-object v1, v8, Llyiahf/vczjk/z88;->OooO0O0:Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/al4;->OooO00o:Llyiahf/vczjk/al4;

    invoke-interface {v1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/jg5;

    return-object v1

    :pswitch_0
    check-cast v8, Llyiahf/vczjk/fq7;

    invoke-virtual {v8}, Llyiahf/vczjk/fq7;->OooOOOO()Ljava/util/List;

    move-result-object v1

    return-object v1

    :pswitch_1
    check-cast v8, Llyiahf/vczjk/n06;

    iget-object v1, v8, Llyiahf/vczjk/n06;->OooO0O0:Llyiahf/vczjk/le3;

    if-eqz v1, :cond_0

    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Ljava/util/List;

    :cond_0
    return-object v7

    :pswitch_2
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v8, Llyiahf/vczjk/qs5;

    invoke-interface {v8, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_3
    check-cast v8, Llyiahf/vczjk/fi4;

    iget-object v1, v8, Llyiahf/vczjk/fi4;->OooOOO0:Llyiahf/vczjk/t4a;

    invoke-interface {v1}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v1

    const-string v2, "getUpperBounds(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-static {v1, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/uk4;

    new-instance v4, Llyiahf/vczjk/di4;

    invoke-direct {v4, v3, v7}, Llyiahf/vczjk/di4;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    return-object v2

    :pswitch_4
    new-instance v1, Llyiahf/vczjk/pg4;

    check-cast v8, Llyiahf/vczjk/qg4;

    invoke-direct {v1, v8}, Llyiahf/vczjk/pg4;-><init>(Llyiahf/vczjk/qg4;)V

    return-object v1

    :pswitch_5
    new-instance v1, Llyiahf/vczjk/ng4;

    check-cast v8, Llyiahf/vczjk/og4;

    invoke-direct {v1, v8}, Llyiahf/vczjk/ng4;-><init>(Llyiahf/vczjk/og4;)V

    return-object v1

    :pswitch_6
    new-instance v1, Llyiahf/vczjk/jg4;

    check-cast v8, Llyiahf/vczjk/kg4;

    invoke-direct {v1, v8}, Llyiahf/vczjk/jg4;-><init>(Llyiahf/vczjk/kg4;)V

    return-object v1

    :pswitch_7
    check-cast v8, Llyiahf/vczjk/yf4;

    invoke-interface {v8}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zl5;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/gz7;

    move-result-object v1

    return-object v1

    :pswitch_8
    check-cast v8, Llyiahf/vczjk/de4;

    iget-object v1, v8, Llyiahf/vczjk/de4;->OooO0OO:Llyiahf/vczjk/tr4;

    iget-object v1, v1, Llyiahf/vczjk/tr4;->OooOo:Llyiahf/vczjk/o45;

    sget-object v2, Llyiahf/vczjk/tr4;->OooOoo0:[Llyiahf/vczjk/th4;

    aget-object v2, v2, v6

    invoke-static {v1, v2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_2
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/tm7;

    iget-object v4, v8, Llyiahf/vczjk/de4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v4, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object v5, v8, Llyiahf/vczjk/de4;->OooO0OO:Llyiahf/vczjk/tr4;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v4, v5, v3}, Llyiahf/vczjk/l82;->OooO00o(Llyiahf/vczjk/hh6;Llyiahf/vczjk/tm7;)Llyiahf/vczjk/s82;

    move-result-object v3

    if-eqz v3, :cond_2

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    invoke-static {v2}, Llyiahf/vczjk/ls6;->OooOOO0(Ljava/util/ArrayList;)Llyiahf/vczjk/ct8;

    move-result-object v1

    new-array v2, v6, [Llyiahf/vczjk/jg5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ct8;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Llyiahf/vczjk/jg5;

    return-object v1

    :pswitch_9
    check-cast v8, Llyiahf/vczjk/jd4;

    iget-object v1, v8, Llyiahf/vczjk/jd4;->OooO0o:Llyiahf/vczjk/gd4;

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/gd4;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/id4;

    iput-object v7, v8, Llyiahf/vczjk/jd4;->OooO0o:Llyiahf/vczjk/gd4;

    return-object v1

    :cond_4
    new-instance v1, Ljava/lang/AssertionError;

    const-string v2, "JvmBuiltins instance has not been initialized properly"

    invoke-direct {v1, v2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1

    :pswitch_a
    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v1

    check-cast v8, Llyiahf/vczjk/ad4;

    iget-object v2, v8, Llyiahf/vczjk/ad4;->OooO00o:Llyiahf/vczjk/yq7;

    invoke-virtual {v2}, Llyiahf/vczjk/yq7;->getDescription()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    iget-object v2, v8, Llyiahf/vczjk/ad4;->OooO0O0:Llyiahf/vczjk/yq7;

    if-eqz v2, :cond_5

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "under-migration:"

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yq7;->getDescription()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    :cond_5
    iget-object v2, v8, Llyiahf/vczjk/ad4;->OooO0OO:Ljava/util/Map;

    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "@"

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v5, 0x3a

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/yq7;

    invoke-virtual {v3}, Llyiahf/vczjk/yq7;->getDescription()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v1

    new-array v2, v6, [Ljava/lang/String;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/y05;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Ljava/lang/String;

    return-object v1

    :pswitch_b
    check-cast v8, Llyiahf/vczjk/u64;

    iget-object v1, v8, Llyiahf/vczjk/z54;->OooO0Oo:Llyiahf/vczjk/y54;

    instance-of v2, v1, Llyiahf/vczjk/vl7;

    if-eqz v2, :cond_7

    sget-object v2, Llyiahf/vczjk/c64;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vl7;

    invoke-virtual {v1}, Llyiahf/vczjk/vl7;->OooO00o()Ljava/util/ArrayList;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/c64;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/ry;

    move-result-object v1

    goto :goto_3

    :cond_7
    instance-of v2, v1, Llyiahf/vczjk/hm7;

    if-eqz v2, :cond_8

    sget-object v2, Llyiahf/vczjk/c64;->OooO00o:Ljava/lang/Object;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/c64;->OooO00o(Ljava/util/List;)Llyiahf/vczjk/ry;

    move-result-object v1

    goto :goto_3

    :cond_8
    move-object v1, v7

    :goto_3
    if-eqz v1, :cond_9

    sget-object v2, Llyiahf/vczjk/a64;->OooO0O0:Llyiahf/vczjk/qt5;

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v2, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v3}, Llyiahf/vczjk/lc5;->o00oO0O(Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v7

    :cond_9
    if-nez v7, :cond_a

    goto :goto_4

    :cond_a
    move-object v4, v7

    :goto_4
    return-object v4

    :pswitch_c
    sget-object v1, Llyiahf/vczjk/c64;->OooO00o:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/t64;

    iget-object v1, v8, Llyiahf/vczjk/z54;->OooO0Oo:Llyiahf/vczjk/y54;

    instance-of v2, v1, Llyiahf/vczjk/hm7;

    if-eqz v2, :cond_b

    check-cast v1, Llyiahf/vczjk/hm7;

    goto :goto_5

    :cond_b
    move-object v1, v7

    :goto_5
    if-eqz v1, :cond_c

    sget-object v2, Llyiahf/vczjk/c64;->OooO0O0:Ljava/lang/Object;

    iget-object v1, v1, Llyiahf/vczjk/hm7;->OooO0O0:Ljava/lang/Enum;

    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sk4;

    if-eqz v1, :cond_c

    new-instance v2, Llyiahf/vczjk/zp2;

    sget-object v3, Llyiahf/vczjk/w09;->OooOo0O:Llyiahf/vczjk/hc3;

    const-string v5, "topLevelFqName"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/hy0;

    invoke-virtual {v3}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v6

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-direct {v5, v6, v3}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-direct {v2, v5, v1}, Llyiahf/vczjk/zp2;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)V

    goto :goto_6

    :cond_c
    move-object v2, v7

    :goto_6
    if-eqz v2, :cond_d

    sget-object v1, Llyiahf/vczjk/a64;->OooO0OO:Llyiahf/vczjk/qt5;

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v3}, Llyiahf/vczjk/lc5;->o00oO0O(Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object v7

    :cond_d
    if-nez v7, :cond_e

    goto :goto_7

    :cond_e
    move-object v4, v7

    :goto_7
    return-object v4

    :pswitch_d
    check-cast v8, Llyiahf/vczjk/f24;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v7

    :pswitch_e
    check-cast v8, Llyiahf/vczjk/kh3;

    invoke-virtual {v8}, Llyiahf/vczjk/kh3;->OooO0oo()Ljava/util/List;

    move-result-object v1

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    iget-object v13, v8, Llyiahf/vczjk/kh3;->OooO0O0:Llyiahf/vczjk/oo0o0Oo;

    invoke-interface {v13}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v5

    const-string v6, "getSupertypes(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v5, Ljava/lang/Iterable;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_8
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_f

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/uk4;

    invoke-virtual {v9}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v9

    invoke-static {v9, v7, v3}, Llyiahf/vczjk/kh6;->OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;

    move-result-object v9

    check-cast v9, Ljava/lang/Iterable;

    invoke-static {v9, v6}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_8

    :cond_f
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_10
    :goto_9
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_11

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    instance-of v7, v6, Llyiahf/vczjk/eo0;

    if-eqz v7, :cond_10

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_9

    :cond_11
    new-instance v5, Ljava/util/LinkedHashMap;

    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_13

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Llyiahf/vczjk/eo0;

    invoke-interface {v7}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v7

    invoke-virtual {v5, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_12

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5, v7, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_12
    check-cast v9, Ljava/util/List;

    invoke-interface {v9, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_a

    :cond_13
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_14
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1a

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/Map$Entry;

    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v6

    const-string v7, "component1(...)"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v10, v6

    check-cast v10, Llyiahf/vczjk/qt5;

    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/LinkedHashMap;

    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_16

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v9, v7

    check-cast v9, Llyiahf/vczjk/eo0;

    instance-of v9, v9, Llyiahf/vczjk/rf3;

    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v9

    invoke-virtual {v6, v9}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    if-nez v11, :cond_15

    new-instance v11, Ljava/util/ArrayList;

    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v6, v9, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_15
    check-cast v11, Ljava/util/List;

    invoke-interface {v11, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_b

    :cond_16
    invoke-virtual {v6}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_c
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_14

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/Map$Entry;

    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/lang/Boolean;

    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    invoke-interface {v6}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v6

    move-object v11, v6

    check-cast v11, Ljava/util/List;

    sget-object v9, Llyiahf/vczjk/ng6;->OooO0OO:Llyiahf/vczjk/ng6;

    if-eqz v7, :cond_19

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :cond_17
    :goto_d
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_18

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v12

    move-object v14, v12

    check-cast v14, Llyiahf/vczjk/rf3;

    check-cast v14, Llyiahf/vczjk/w02;

    invoke-virtual {v14}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v14

    invoke-static {v14, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_17

    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_d

    :cond_18
    move-object v12, v6

    goto :goto_e

    :cond_19
    move-object v12, v2

    :goto_e
    new-instance v14, Llyiahf/vczjk/jh3;

    invoke-direct {v14, v4, v8}, Llyiahf/vczjk/jh3;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/kh3;)V

    invoke-virtual/range {v9 .. v14}, Llyiahf/vczjk/ng6;->OooO0oo(Llyiahf/vczjk/qt5;Ljava/util/Collection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/c6a;)V

    goto :goto_c

    :cond_1a
    invoke-static {v4}, Llyiahf/vczjk/t51;->OooOo0(Ljava/util/ArrayList;)Ljava/util/List;

    move-result-object v2

    invoke-static {v2, v1}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v1

    return-object v1

    :pswitch_f
    check-cast v8, Ljava/util/List;

    return-object v8

    :pswitch_10
    check-cast v8, Llyiahf/vczjk/qp2;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/util/HashSet;

    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    iget-object v2, v8, Llyiahf/vczjk/qp2;->OooO0o0:Llyiahf/vczjk/rp2;

    iget-object v2, v2, Llyiahf/vczjk/rp2;->OooOo0:Llyiahf/vczjk/o45;

    invoke-virtual {v2}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Set;

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qt5;

    sget-object v4, Llyiahf/vczjk/h16;->OooOOo:Llyiahf/vczjk/h16;

    invoke-virtual {v8, v3, v4}, Llyiahf/vczjk/qp2;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v5

    invoke-interface {v1, v5}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v8, v3, v4}, Llyiahf/vczjk/qp2;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v3

    invoke-interface {v1, v3}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    goto :goto_f

    :cond_1b
    return-object v1

    :pswitch_11
    check-cast v8, Llyiahf/vczjk/w82;

    iget-object v1, v8, Llyiahf/vczjk/w82;->OooOoO:Llyiahf/vczjk/u72;

    iget-object v2, v1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s72;

    iget-object v2, v2, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    iget-object v3, v8, Llyiahf/vczjk/w82;->OooOoOO:Llyiahf/vczjk/md7;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rt5;

    invoke-interface {v2, v3, v1}, Llyiahf/vczjk/zn;->OooO(Llyiahf/vczjk/md7;Llyiahf/vczjk/rt5;)Ljava/util/ArrayList;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    return-object v1

    :pswitch_12
    check-cast v8, Llyiahf/vczjk/hk0;

    iget-object v1, v8, Llyiahf/vczjk/hk0;->OooOo:Llyiahf/vczjk/pb7;

    iget-object v1, v1, Llyiahf/vczjk/pb7;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Ljava/util/LinkedHashMap;

    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    move-result-object v1

    check-cast v1, Ljava/util/Collection;

    check-cast v1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1c
    :goto_10
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/hy0;

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->OooO0oO()Z

    move-result v6

    if-nez v6, :cond_1c

    sget-object v6, Llyiahf/vczjk/gy0;->OooO0OO:Ljava/util/Set;

    invoke-interface {v6, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1c

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    :cond_1d
    new-instance v1, Ljava/util/ArrayList;

    invoke-static {v2, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_11
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1e

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hy0;

    invoke-virtual {v3}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_11

    :cond_1e
    return-object v1

    :pswitch_13
    check-cast v8, Llyiahf/vczjk/r82;

    invoke-virtual {v8}, Llyiahf/vczjk/r82;->OooOOO()Ljava/util/Set;

    move-result-object v1

    if-nez v1, :cond_1f

    goto :goto_12

    :cond_1f
    invoke-virtual {v8}, Llyiahf/vczjk/r82;->OooOOO0()Ljava/util/Set;

    move-result-object v2

    iget-object v3, v8, Llyiahf/vczjk/r82;->OooO0OO:Llyiahf/vczjk/q82;

    iget-object v3, v3, Llyiahf/vczjk/q82;->OooO0OO:Ljava/util/LinkedHashMap;

    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    move-result-object v3

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v2, v3}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v2

    check-cast v1, Ljava/lang/Iterable;

    invoke-static {v2, v1}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v7

    :goto_12
    return-object v7

    :pswitch_14
    check-cast v8, Llyiahf/vczjk/ld9;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/util/HashSet;

    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    iget-object v2, v8, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/h82;

    iget-object v4, v2, Llyiahf/vczjk/h82;->OooOoO:Llyiahf/vczjk/f82;

    invoke-virtual {v4}, Llyiahf/vczjk/o0O00000;->OooO()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_20
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_23

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/uk4;

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v5

    invoke-static {v5, v7, v3}, Llyiahf/vczjk/kh6;->OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_21
    :goto_13
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_20

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/v02;

    instance-of v8, v6, Llyiahf/vczjk/ho8;

    if-nez v8, :cond_22

    instance-of v8, v6, Llyiahf/vczjk/sa7;

    if-eqz v8, :cond_21

    :cond_22
    check-cast v6, Llyiahf/vczjk/eo0;

    invoke-interface {v6}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v1, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_13

    :cond_23
    iget-object v3, v2, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-virtual {v3}, Llyiahf/vczjk/zb7;->ooOO()Ljava/util/List;

    move-result-object v4

    const-string v5, "getFunctionList(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_14
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    iget-object v6, v2, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    if-eqz v5, :cond_24

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/pc7;

    iget-object v6, v6, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/rt5;

    invoke-virtual {v5}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v5

    invoke-static {v6, v5}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {v1, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_14

    :cond_24
    invoke-virtual {v3}, Llyiahf/vczjk/zb7;->o0ooOoO()Ljava/util/List;

    move-result-object v2

    const-string v3, "getPropertyList(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_15
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_25

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xc7;

    iget-object v4, v6, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/rt5;

    invoke-virtual {v3}, Llyiahf/vczjk/xc7;->Oooo0o()I

    move-result v3

    invoke-static {v4, v3}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_15

    :cond_25
    invoke-static {v1, v1}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v1

    return-object v1

    :pswitch_15
    check-cast v8, Llyiahf/vczjk/h72;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v8, Llyiahf/vczjk/h72;->OooO00o:Llyiahf/vczjk/l72;

    new-instance v3, Llyiahf/vczjk/l72;

    invoke-direct {v3}, Llyiahf/vczjk/l72;-><init>()V

    const-class v4, Llyiahf/vczjk/l72;

    invoke-virtual {v4}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v5

    :cond_26
    :goto_16
    invoke-virtual {v5}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_2a

    invoke-virtual {v5}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/reflect/Field;

    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v9

    and-int/lit8 v9, v9, 0x8

    if-nez v9, :cond_26

    invoke-virtual {v8, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    invoke-virtual {v8, v2}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    instance-of v10, v9, Llyiahf/vczjk/k72;

    if-eqz v10, :cond_27

    check-cast v9, Llyiahf/vczjk/k72;

    goto :goto_17

    :cond_27
    move-object v9, v7

    :goto_17
    if-nez v9, :cond_28

    goto :goto_16

    :cond_28
    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v10

    const-string v11, "getName(...)"

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v12, "is"

    invoke-static {v10, v12, v6}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    sget-object v10, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v10

    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v12

    invoke-static {v12, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v12}, Ljava/lang/String;->length()I

    move-result v11

    if-lez v11, :cond_29

    invoke-virtual {v12, v6}, Ljava/lang/String;->charAt(I)C

    move-result v11

    invoke-static {v11}, Ljava/lang/Character;->toUpperCase(C)C

    invoke-virtual {v12, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v11

    const-string v12, "substring(...)"

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_29
    check-cast v10, Llyiahf/vczjk/tx0;

    invoke-interface {v10}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    iget-object v9, v9, Llyiahf/vczjk/k72;->OooO00o:Ljava/lang/Object;

    new-instance v10, Llyiahf/vczjk/k72;

    invoke-direct {v10, v9, v3}, Llyiahf/vczjk/k72;-><init>(Ljava/lang/Object;Llyiahf/vczjk/l72;)V

    invoke-virtual {v8, v3, v10}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_16

    :cond_2a
    sget-object v2, Llyiahf/vczjk/h72;->OooO0OO:Llyiahf/vczjk/h72;

    invoke-interface {v3}, Llyiahf/vczjk/j72;->OooOO0O()Ljava/util/Set;

    move-result-object v2

    sget-object v4, Llyiahf/vczjk/w09;->OooOOOo:Llyiahf/vczjk/hc3;

    sget-object v5, Llyiahf/vczjk/w09;->OooOOo0:Llyiahf/vczjk/hc3;

    filled-new-array {v4, v5}, [Llyiahf/vczjk/hc3;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v2

    invoke-interface {v3, v2}, Llyiahf/vczjk/j72;->OooO0o(Ljava/util/LinkedHashSet;)V

    iput-boolean v1, v3, Llyiahf/vczjk/l72;->OooO00o:Z

    new-instance v1, Llyiahf/vczjk/h72;

    invoke-direct {v1, v3}, Llyiahf/vczjk/h72;-><init>(Llyiahf/vczjk/l72;)V

    return-object v1

    :pswitch_16
    check-cast v8, Llyiahf/vczjk/zp8;

    const v1, 0x3c23d70a    # 0.01f

    const/4 v2, 0x0

    cmpl-float v1, v2, v1

    if-lez v1, :cond_2b

    const/high16 v2, 0x3f800000    # 1.0f

    :cond_2b
    iget-object v1, v8, Llyiahf/vczjk/zp8;->OooO:Llyiahf/vczjk/fx9;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/jk2;->OooO0OO:Llyiahf/vczjk/cu1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/cu1;->OooO00o(F)F

    move-result v2

    iget-wide v3, v1, Llyiahf/vczjk/fx9;->OooO00o:J

    iget-wide v5, v1, Llyiahf/vczjk/fx9;->OooO0O0:J

    invoke-static {v3, v4, v5, v6, v2}, Llyiahf/vczjk/v34;->Ooooo00(JJF)J

    move-result-wide v1

    new-instance v3, Llyiahf/vczjk/n21;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/n21;-><init>(J)V

    return-object v3

    :pswitch_17
    check-cast v8, Llyiahf/vczjk/z4a;

    invoke-virtual {v8}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    const-string v2, "getType(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v1

    :pswitch_18
    check-cast v8, Llyiahf/vczjk/wj0;

    iget-object v1, v8, Llyiahf/vczjk/wj0;->OooO00o:Llyiahf/vczjk/hk4;

    iget-object v2, v8, Llyiahf/vczjk/wj0;->OooO0O0:Llyiahf/vczjk/hc3;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v1

    return-object v1

    :pswitch_19
    check-cast v8, Ljava/util/Map;

    invoke-interface {v8}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_18
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_35

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    instance-of v4, v2, [Z

    if-eqz v4, :cond_2c

    check-cast v2, [Z

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([Z)I

    move-result v2

    goto :goto_19

    :cond_2c
    instance-of v4, v2, [C

    if-eqz v4, :cond_2d

    check-cast v2, [C

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([C)I

    move-result v2

    goto :goto_19

    :cond_2d
    instance-of v4, v2, [B

    if-eqz v4, :cond_2e

    check-cast v2, [B

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([B)I

    move-result v2

    goto :goto_19

    :cond_2e
    instance-of v4, v2, [S

    if-eqz v4, :cond_2f

    check-cast v2, [S

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([S)I

    move-result v2

    goto :goto_19

    :cond_2f
    instance-of v4, v2, [I

    if-eqz v4, :cond_30

    check-cast v2, [I

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([I)I

    move-result v2

    goto :goto_19

    :cond_30
    instance-of v4, v2, [F

    if-eqz v4, :cond_31

    check-cast v2, [F

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([F)I

    move-result v2

    goto :goto_19

    :cond_31
    instance-of v4, v2, [J

    if-eqz v4, :cond_32

    check-cast v2, [J

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([J)I

    move-result v2

    goto :goto_19

    :cond_32
    instance-of v4, v2, [D

    if-eqz v4, :cond_33

    check-cast v2, [D

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([D)I

    move-result v2

    goto :goto_19

    :cond_33
    instance-of v4, v2, [Ljava/lang/Object;

    if-eqz v4, :cond_34

    check-cast v2, [Ljava/lang/Object;

    invoke-static {v2}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    move-result v2

    goto :goto_19

    :cond_34
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    :goto_19
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    move-result v3

    mul-int/lit8 v3, v3, 0x7f

    xor-int/2addr v2, v3

    add-int/2addr v6, v2

    goto/16 :goto_18

    :cond_35
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    return-object v1

    :pswitch_1a
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Scope for type parameter "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    check-cast v8, Llyiahf/vczjk/o0O000;

    iget-object v2, v8, Llyiahf/vczjk/o0O000;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qt5;

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    iget-object v2, v8, Llyiahf/vczjk/o0O000;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/o0OoOoOo;

    invoke-virtual {v2}, Llyiahf/vczjk/o0OoOoOo;->getUpperBounds()Ljava/util/List;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/ls6;->OooO0oO(Ljava/lang/String;Ljava/util/Collection;)Llyiahf/vczjk/jg5;

    move-result-object v1

    return-object v1

    :pswitch_1b
    new-instance v1, Llyiahf/vczjk/o0;

    check-cast v8, Llyiahf/vczjk/o0O00000;

    invoke-virtual {v8}, Llyiahf/vczjk/o0O00000;->OooO0o()Ljava/util/Collection;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/o0;-><init>(Ljava/util/Collection;)V

    return-object v1

    :pswitch_1c
    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/v82;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v10}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object v3

    if-nez v3, :cond_36

    goto/16 :goto_23

    :cond_36
    invoke-interface {v3}, Llyiahf/vczjk/by0;->OooOoO()Ljava/util/Collection;

    move-result-object v3

    const-string v4, "getConstructors(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Ljava/lang/Iterable;

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_1a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_41

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ux0;

    sget-object v9, Llyiahf/vczjk/z2a;->o000oOoO:Llyiahf/vczjk/sp3;

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v9, v10, Llyiahf/vczjk/v82;->OooOo00:Llyiahf/vczjk/q45;

    const-string v11, "storageManager"

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v10}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object v11

    if-nez v11, :cond_37

    move-object v11, v7

    goto :goto_1b

    :cond_37
    invoke-virtual {v10}, Llyiahf/vczjk/v82;->o0000O0O()Llyiahf/vczjk/dp8;

    move-result-object v11

    invoke-static {v11}, Llyiahf/vczjk/i5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/i5a;

    move-result-object v11

    :goto_1b
    if-nez v11, :cond_38

    :goto_1c
    move/from16 v24, v1

    :goto_1d
    move-object v15, v7

    move-object/from16 v25, v15

    goto/16 :goto_22

    :cond_38
    move-object v14, v11

    invoke-virtual {v8, v14}, Llyiahf/vczjk/ux0;->o0000oOO(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/ux0;

    move-result-object v11

    if-nez v11, :cond_39

    goto :goto_1c

    :cond_39
    new-instance v15, Llyiahf/vczjk/z2a;

    move-object v12, v8

    check-cast v12, Llyiahf/vczjk/l21;

    invoke-virtual {v12}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v13

    check-cast v8, Llyiahf/vczjk/tf3;

    move-object v12, v14

    invoke-virtual {v8}, Llyiahf/vczjk/tf3;->getKind()I

    move-result v14

    move/from16 v24, v1

    const-string v1, "getKind(...)"

    invoke-static {v14, v1}, Llyiahf/vczjk/u81;->OooOoO0(ILjava/lang/String;)V

    move-object v1, v8

    move-object v8, v15

    invoke-virtual {v10}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v15

    const-string v6, "getSource(...)"

    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v6, v12

    const/4 v12, 0x0

    invoke-direct/range {v8 .. v15}, Llyiahf/vczjk/z2a;-><init>(Llyiahf/vczjk/w59;Llyiahf/vczjk/a3a;Llyiahf/vczjk/ux0;Llyiahf/vczjk/y2a;Llyiahf/vczjk/ko;ILlyiahf/vczjk/sx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v13

    if-eqz v13, :cond_40

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/4 v15, 0x0

    move-object v14, v6

    move-object v12, v8

    invoke-static/range {v12 .. v17}, Llyiahf/vczjk/tf3;->o0000OO0(Llyiahf/vczjk/rf3;Ljava/util/List;Llyiahf/vczjk/i5a;ZZ[Z)Ljava/util/ArrayList;

    move-result-object v20

    if-nez v20, :cond_3a

    goto :goto_1d

    :cond_3a
    check-cast v11, Llyiahf/vczjk/tf3;

    iget-object v9, v11, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-virtual {v9}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/u34;->Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v9

    invoke-virtual {v10}, Llyiahf/vczjk/v82;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v11

    invoke-static {v9, v11}, Llyiahf/vczjk/ll6;->OooOOo(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/dp8;

    move-result-object v21

    iget-object v9, v1, Llyiahf/vczjk/tf3;->OooOoO0:Llyiahf/vczjk/mp4;

    sget-object v11, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    if-eqz v9, :cond_3b

    invoke-virtual {v9}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v9

    sget-object v12, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v6, v9, v12}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v9

    invoke-static {v8, v9, v11}, Llyiahf/vczjk/dn8;->OoooO0O(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/mp4;

    move-result-object v9

    move-object/from16 v16, v9

    goto :goto_1e

    :cond_3b
    move-object/from16 v16, v7

    :goto_1e
    invoke-virtual {v10}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object v9

    if-eqz v9, :cond_3e

    invoke-virtual {v1}, Llyiahf/vczjk/tf3;->o00Oo0()Ljava/util/List;

    move-result-object v1

    const-string v12, "getContextReceiverParameters(...)"

    invoke-static {v1, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v12, Ljava/util/ArrayList;

    invoke-static {v1, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-direct {v12, v13}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    const/4 v13, 0x0

    :goto_1f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_3d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    add-int/lit8 v15, v13, 0x1

    if-ltz v13, :cond_3c

    check-cast v14, Llyiahf/vczjk/mp4;

    invoke-virtual {v14}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v5

    move-object/from16 v25, v7

    sget-object v7, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v6, v5, v7}, Llyiahf/vczjk/i5a;->OooO0oO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v5

    invoke-virtual {v14}, Llyiahf/vczjk/mp4;->o0000O0()Llyiahf/vczjk/vi7;

    move-result-object v7

    const-string v14, "null cannot be cast to non-null type org.jetbrains.kotlin.resolve.scopes.receivers.ImplicitContextReceiver"

    invoke-static {v7, v14}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v7, Llyiahf/vczjk/ln1;

    invoke-virtual {v7}, Llyiahf/vczjk/ln1;->o0000oo()Llyiahf/vczjk/qt5;

    move-result-object v7

    new-instance v14, Llyiahf/vczjk/mp4;

    new-instance v0, Llyiahf/vczjk/ln1;

    invoke-direct {v0, v9, v5, v7}, Llyiahf/vczjk/ln1;-><init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/qt5;)V

    sget-object v5, Llyiahf/vczjk/xt5;->OooO00o:Llyiahf/vczjk/on7;

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v7, Llyiahf/vczjk/xt5;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v7, 0x5f

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-direct {v14, v9, v0, v11, v5}, Llyiahf/vczjk/mp4;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/l21;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v12, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v0, p0

    move v13, v15

    move-object/from16 v7, v25

    const/16 v5, 0xa

    goto :goto_1f

    :cond_3c
    move-object/from16 v25, v7

    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v25

    :cond_3d
    move-object/from16 v18, v12

    :goto_20
    move-object/from16 v25, v7

    goto :goto_21

    :cond_3e
    move-object/from16 v18, v2

    goto :goto_20

    :goto_21
    invoke-virtual {v10}, Llyiahf/vczjk/v82;->OooOo00()Ljava/util/List;

    move-result-object v19

    sget-object v22, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    const/16 v17, 0x0

    iget-object v0, v10, Llyiahf/vczjk/v82;->OooOo0:Llyiahf/vczjk/q72;

    move-object/from16 v23, v0

    move-object v15, v8

    invoke-virtual/range {v15 .. v23}, Llyiahf/vczjk/tf3;->o0000OO(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;)V

    :goto_22
    if-eqz v15, :cond_3f

    invoke-virtual {v4, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_3f
    move-object/from16 v0, p0

    move/from16 v1, v24

    move-object/from16 v7, v25

    const/16 v5, 0xa

    const/4 v6, 0x0

    goto/16 :goto_1a

    :cond_40
    move-object/from16 v25, v7

    const/16 v0, 0x1c

    invoke-static {v0}, Llyiahf/vczjk/tf3;->o00000O0(I)V

    throw v25

    :cond_41
    move-object v2, v4

    :goto_23
    return-object v2

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
