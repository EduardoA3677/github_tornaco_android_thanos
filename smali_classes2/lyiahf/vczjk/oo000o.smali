.class public final Llyiahf/vczjk/oo000o;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/oo000o;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/oo000o;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/by0;Llyiahf/vczjk/pg7;Llyiahf/vczjk/dp8;Llyiahf/vczjk/a74;)V
    .locals 0

    const/16 p2, 0x16

    iput p2, p0, Llyiahf/vczjk/oo000o;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oo000o;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    const-string v2, "fqName"

    const-string v3, "kotlinTypeRefiner"

    const-string v4, "getType(...)"

    const/16 v5, 0xa

    sget-object v7, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v8, 0x0

    const/4 v9, 0x1

    const-string v10, "it"

    iget-object v11, v1, Llyiahf/vczjk/oo000o;->OooOOO:Ljava/lang/Object;

    iget v12, v1, Llyiahf/vczjk/oo000o;->OooOOO0:I

    packed-switch v12, :pswitch_data_0

    check-cast v0, Llyiahf/vczjk/cm5;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/uk4;

    return-object v11

    :pswitch_0
    check-cast v0, Llyiahf/vczjk/w4a;

    iget-object v2, v0, Llyiahf/vczjk/w4a;->OooO00o:Llyiahf/vczjk/t4a;

    check-cast v11, Llyiahf/vczjk/qx7;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v12, v0, Llyiahf/vczjk/w4a;->OooO0O0:Llyiahf/vczjk/a74;

    iget-object v0, v12, Llyiahf/vczjk/a74;->OooO0o0:Ljava/util/Set;

    if-eqz v0, :cond_0

    invoke-interface {v2}, Llyiahf/vczjk/t4a;->OooO00o()Llyiahf/vczjk/t4a;

    move-result-object v3

    invoke-interface {v0, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v11, v12}, Llyiahf/vczjk/qx7;->OooOOOo(Llyiahf/vczjk/a74;)Llyiahf/vczjk/iaa;

    move-result-object v0

    goto/16 :goto_5

    :cond_0
    invoke-interface {v2}, Llyiahf/vczjk/gz0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v3

    const-string v4, "getDefaultType(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ljava/util/LinkedHashSet;

    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-static {v3, v3, v4, v0}, Llyiahf/vczjk/fu6;->OooOO0O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/dp8;Ljava/util/LinkedHashSet;Ljava/util/Set;)V

    invoke-static {v4, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-static {v3}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v3

    const/16 v5, 0x10

    if-ge v3, v5, :cond_1

    move v3, v5

    :cond_1
    new-instance v5, Ljava/util/LinkedHashMap;

    invoke-direct {v5, v3}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t4a;

    if-eqz v0, :cond_3

    invoke-interface {v0, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_1

    :cond_2
    invoke-static {v4, v12}, Llyiahf/vczjk/l5a;->OooOO0O(Llyiahf/vczjk/t4a;Llyiahf/vczjk/a74;)Llyiahf/vczjk/z4a;

    move-result-object v6

    goto :goto_4

    :cond_3
    :goto_1
    iget-object v6, v12, Llyiahf/vczjk/a74;->OooO0o0:Ljava/util/Set;

    if-eqz v6, :cond_4

    invoke-static {v6, v2}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v6

    :goto_2
    move-object v15, v6

    goto :goto_3

    :cond_4
    invoke-static {v2}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v6

    goto :goto_2

    :goto_3
    const/4 v14, 0x0

    const/16 v17, 0x2f

    const/4 v13, 0x0

    const/16 v16, 0x0

    invoke-static/range {v12 .. v17}, Llyiahf/vczjk/a74;->OooO00o(Llyiahf/vczjk/a74;Llyiahf/vczjk/d74;ZLjava/util/Set;Llyiahf/vczjk/dp8;I)Llyiahf/vczjk/a74;

    move-result-object v6

    invoke-virtual {v11, v4, v6}, Llyiahf/vczjk/qx7;->OooOOo0(Llyiahf/vczjk/t4a;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v6

    invoke-static {v4, v12, v11, v6}, Llyiahf/vczjk/xj0;->OooOOO0(Llyiahf/vczjk/t4a;Llyiahf/vczjk/a74;Llyiahf/vczjk/qx7;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v6

    :goto_4
    invoke-interface {v4}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v4

    new-instance v7, Llyiahf/vczjk/xn6;

    invoke-direct {v7, v4, v6}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v7}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {v7}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v6

    invoke-interface {v5, v4, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_5
    new-instance v0, Llyiahf/vczjk/g19;

    invoke-direct {v0, v5, v9}, Llyiahf/vczjk/g19;-><init>(Ljava/lang/Object;I)V

    new-instance v3, Llyiahf/vczjk/i5a;

    invoke-direct {v3, v0}, Llyiahf/vczjk/i5a;-><init>(Llyiahf/vczjk/g5a;)V

    invoke-interface {v2}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v0

    const-string v2, "getUpperBounds(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v11, v3, v0, v12}, Llyiahf/vczjk/qx7;->OooOo0(Llyiahf/vczjk/i5a;Ljava/util/List;Llyiahf/vczjk/a74;)Llyiahf/vczjk/gh8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/gh8;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/gh8;->OooO00o()I

    move-result v2

    if-ne v2, v9, :cond_6

    invoke-static {v0}, Llyiahf/vczjk/d21;->o00000Oo(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uk4;

    goto :goto_5

    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v2, "Should only be one computed upper bound if no need to intersect all bounds"

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_7
    invoke-virtual {v11, v12}, Llyiahf/vczjk/qx7;->OooOOOo(Llyiahf/vczjk/a74;)Llyiahf/vczjk/iaa;

    move-result-object v0

    :goto_5
    return-object v0

    :pswitch_1
    check-cast v0, Ltornaco/apps/thanox/core/proto/common/CommonApiRes;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Lgithub/tornaco/android/thanos/core/ICallback;

    :try_start_0
    invoke-virtual {v0}, Lcom/google/protobuf/AbstractMessageLite;->toByteArray()[B

    move-result-object v0

    invoke-interface {v11, v0}, Lgithub/tornaco/android/thanos/core/ICallback;->receive([B)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_6

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    :goto_6
    return-object v7

    :pswitch_2
    check-cast v0, Llyiahf/vczjk/ww2;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/n07;

    iget v0, v0, Llyiahf/vczjk/ww2;->OooO00o:I

    invoke-virtual {v11, v0}, Llyiahf/vczjk/n07;->OooO00o(I)V

    return-object v7

    :pswitch_3
    check-cast v0, Llyiahf/vczjk/eo0;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v0

    check-cast v11, Llyiahf/vczjk/tca;

    iget v2, v11, Llyiahf/vczjk/tca;->OooOo0:I

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tca;

    check-cast v0, Llyiahf/vczjk/bda;

    invoke-virtual {v0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :pswitch_4
    check-cast v0, Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->isSynthetic()Z

    move-result v2

    if-eqz v2, :cond_8

    goto :goto_8

    :cond_8
    check-cast v11, Llyiahf/vczjk/cm7;

    iget-object v2, v11, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/Class;->isEnum()Z

    move-result v2

    if-eqz v2, :cond_c

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v3, "values"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_a

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v0

    const-string v2, "getParameterTypes(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v0, v0

    if-nez v0, :cond_9

    move v0, v9

    goto :goto_7

    :cond_9
    const/4 v0, 0x0

    goto :goto_7

    :cond_a
    const-string v3, "valueOf"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_9

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v0

    const-class v2, Ljava/lang/String;

    filled-new-array {v2}, [Ljava/lang/Class;

    move-result-object v2

    invoke-static {v0, v2}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result v0

    :goto_7
    if-nez v0, :cond_b

    goto :goto_9

    :cond_b
    :goto_8
    const/4 v6, 0x0

    goto :goto_a

    :cond_c
    :goto_9
    move v6, v9

    :goto_a
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_5
    check-cast v0, Llyiahf/vczjk/al4;

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/by0;

    invoke-static {v11}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    return-object v8

    :pswitch_6
    check-cast v0, Ljava/lang/Throwable;

    check-cast v11, Llyiahf/vczjk/yp0;

    invoke-virtual {v11, v7}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-object v7

    :pswitch_7
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v11, Llyiahf/vczjk/dt8;

    invoke-virtual {v11, v0}, Llyiahf/vczjk/dt8;->add(Ljava/lang/Object;)Z

    return-object v7

    :pswitch_8
    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/hc3;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v11, Llyiahf/vczjk/era;

    iget-object v0, v11, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_d
    :goto_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_10

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/Map$Entry;

    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/hc3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_f

    const-string v6, "packageName"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v6, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v6}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v6

    if-eqz v6, :cond_e

    move-object v6, v8

    goto :goto_c

    :cond_e
    invoke-virtual {v3}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v6

    :goto_c
    invoke-static {v6, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_d

    :cond_f
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v2, v5, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_b

    :cond_10
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_11

    goto :goto_d

    :cond_11
    move-object v2, v8

    :goto_d
    if-nez v2, :cond_12

    goto :goto_f

    :cond_12
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_13

    move-object v0, v8

    goto :goto_e

    :cond_13
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-nez v2, :cond_14

    goto :goto_e

    :cond_14
    move-object v2, v0

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/hc3;

    invoke-static {v2, v3}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v2, v2, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    :cond_15
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Ljava/util/Map$Entry;

    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/hc3;

    invoke-static {v6, v3}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v6, v6, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v6

    if-le v2, v6, :cond_16

    move-object v0, v5

    move v2, v6

    :cond_16
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-nez v5, :cond_15

    :goto_e
    check-cast v0, Ljava/util/Map$Entry;

    if-eqz v0, :cond_17

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v8

    :cond_17
    :goto_f
    return-object v8

    :pswitch_9
    check-cast v0, Llyiahf/vczjk/hc3;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/dm5;

    iget-object v2, v11, Llyiahf/vczjk/dm5;->OooOo0:Llyiahf/vczjk/yh6;

    check-cast v2, Llyiahf/vczjk/xh6;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v11, Llyiahf/vczjk/dm5;->OooOOo:Llyiahf/vczjk/q45;

    const-string v3, "storageManager"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/hw4;

    invoke-direct {v3, v11, v0, v2}, Llyiahf/vczjk/hw4;-><init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;Llyiahf/vczjk/q45;)V

    return-object v3

    :pswitch_a
    check-cast v0, Llyiahf/vczjk/qm7;

    const-string v2, "typeParameter"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/rr0;

    iget-object v2, v11, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    check-cast v2, Ljava/util/LinkedHashMap;

    invoke-virtual {v2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    if-eqz v2, :cond_18

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    new-instance v8, Llyiahf/vczjk/hs4;

    iget-object v3, v11, Llyiahf/vczjk/rr0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ld9;

    const-string v4, "<this>"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/ld9;

    iget-object v5, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/s64;

    iget-object v3, v3, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    invoke-direct {v4, v5, v11, v3}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    iget-object v3, v11, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/x02;

    invoke-interface {v3}, Llyiahf/vczjk/gm;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/l4a;->OooOOo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ld9;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/rr0;->OooOOO:I

    add-int/2addr v5, v2

    invoke-direct {v8, v4, v0, v5, v3}, Llyiahf/vczjk/hs4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/qm7;ILlyiahf/vczjk/x02;)V

    :cond_18
    return-object v8

    :pswitch_b
    check-cast v0, Llyiahf/vczjk/jg5;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/h16;->OooOOo0:Llyiahf/vczjk/h16;

    check-cast v11, Llyiahf/vczjk/qt5;

    invoke-interface {v0, v11, v2}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v0

    return-object v0

    :pswitch_c
    check-cast v0, Llyiahf/vczjk/al4;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v12, Llyiahf/vczjk/rr4;

    move-object v14, v11

    check-cast v14, Llyiahf/vczjk/nr4;

    iget-object v13, v14, Llyiahf/vczjk/nr4;->OooOo0O:Llyiahf/vczjk/ld9;

    iget-object v0, v14, Llyiahf/vczjk/nr4;->OooOo0:Llyiahf/vczjk/by0;

    if-eqz v0, :cond_19

    move/from16 v16, v9

    goto :goto_10

    :cond_19
    const/16 v16, 0x0

    :goto_10
    iget-object v0, v14, Llyiahf/vczjk/nr4;->OooOoo:Llyiahf/vczjk/rr4;

    iget-object v15, v14, Llyiahf/vczjk/nr4;->OooOo00:Llyiahf/vczjk/cm7;

    move-object/from16 v17, v0

    invoke-direct/range {v12 .. v17}, Llyiahf/vczjk/rr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/by0;Llyiahf/vczjk/cm7;ZLlyiahf/vczjk/rr4;)V

    return-object v12

    :pswitch_d
    check-cast v0, Llyiahf/vczjk/sl7;

    const-string v2, "annotation"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/a64;->OooO00o:Llyiahf/vczjk/qt5;

    check-cast v11, Llyiahf/vczjk/lr4;

    iget-object v2, v11, Llyiahf/vczjk/lr4;->OooOOO0:Llyiahf/vczjk/ld9;

    iget-boolean v3, v11, Llyiahf/vczjk/lr4;->OooOOOO:Z

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/a64;->OooO0O0(Llyiahf/vczjk/sl7;Llyiahf/vczjk/ld9;Z)Llyiahf/vczjk/f07;

    move-result-object v0

    return-object v0

    :pswitch_e
    check-cast v0, Llyiahf/vczjk/al4;

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/m34;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v11, Llyiahf/vczjk/m34;->OooO0O0:Ljava/util/LinkedHashSet;

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    const/4 v6, 0x0

    :goto_11
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1a

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/uk4;

    invoke-virtual {v4, v0}, Llyiahf/vczjk/uk4;->o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v6, v9

    goto :goto_11

    :cond_1a
    if-nez v6, :cond_1b

    goto :goto_12

    :cond_1b
    iget-object v2, v11, Llyiahf/vczjk/m34;->OooO00o:Llyiahf/vczjk/uk4;

    if-eqz v2, :cond_1c

    invoke-virtual {v2, v0}, Llyiahf/vczjk/uk4;->o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;

    move-result-object v8

    :cond_1c
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0, v3}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    new-instance v2, Llyiahf/vczjk/m34;

    invoke-direct {v2, v0}, Llyiahf/vczjk/m34;-><init>(Ljava/util/AbstractCollection;)V

    iput-object v8, v2, Llyiahf/vczjk/m34;->OooO00o:Llyiahf/vczjk/uk4;

    move-object v8, v2

    :goto_12
    if-nez v8, :cond_1d

    goto :goto_13

    :cond_1d
    move-object v11, v8

    :goto_13
    invoke-virtual {v11}, Llyiahf/vczjk/m34;->OooO0o()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    :pswitch_f
    check-cast v0, Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-interface {v11, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_10
    check-cast v0, Llyiahf/vczjk/hy0;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/hk0;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    return-object v0

    :pswitch_11
    check-cast v0, Llyiahf/vczjk/eo0;

    if-eqz v0, :cond_1e

    check-cast v11, Llyiahf/vczjk/m72;

    iget-object v2, v11, Llyiahf/vczjk/m72;->Oooo00O:Llyiahf/vczjk/kq2;

    invoke-interface {v2, v0}, Llyiahf/vczjk/kq2;->OooO0O0(Llyiahf/vczjk/eo0;)V

    return-object v7

    :cond_1e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v2, "Argument for @NotNull parameter \'descriptor\' of kotlin/reflect/jvm/internal/impl/load/java/components/DescriptorResolverUtils$1$1.invoke must not be null"

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_12
    check-cast v0, Llyiahf/vczjk/cm5;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v0

    check-cast v11, Llyiahf/vczjk/q47;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/hk4;->OooOOo(Llyiahf/vczjk/q47;)Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    :pswitch_13
    check-cast v0, Llyiahf/vczjk/fy0;

    const-string v2, "key"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/gy0;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v11, Llyiahf/vczjk/gy0;->OooO00o:Llyiahf/vczjk/s72;

    iget-object v3, v2, Llyiahf/vczjk/s72;->OooOO0O:Ljava/lang/Iterable;

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_1f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    iget-object v5, v0, Llyiahf/vczjk/fy0;->OooO00o:Llyiahf/vczjk/hy0;

    if-eqz v4, :cond_20

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/dy0;

    invoke-interface {v4, v5}, Llyiahf/vczjk/dy0;->OooO0O0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object v4

    if-eqz v4, :cond_1f

    move-object v8, v4

    goto/16 :goto_18

    :cond_20
    sget-object v3, Llyiahf/vczjk/gy0;->OooO0OO:Ljava/util/Set;

    invoke-interface {v3, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_21

    goto/16 :goto_18

    :cond_21
    iget-object v0, v0, Llyiahf/vczjk/fy0;->OooO0O0:Llyiahf/vczjk/vx0;

    if-nez v0, :cond_22

    iget-object v0, v2, Llyiahf/vczjk/s72;->OooO0Oo:Llyiahf/vczjk/wx0;

    invoke-interface {v0, v5}, Llyiahf/vczjk/wx0;->Oooooo0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/vx0;

    move-result-object v0

    if-nez v0, :cond_22

    goto/16 :goto_18

    :cond_22
    invoke-virtual {v5}, Llyiahf/vczjk/hy0;->OooO0o0()Llyiahf/vczjk/hy0;

    move-result-object v3

    iget-object v14, v0, Llyiahf/vczjk/vx0;->OooO00o:Llyiahf/vczjk/rt5;

    iget-object v4, v0, Llyiahf/vczjk/vx0;->OooO0O0:Llyiahf/vczjk/zb7;

    iget-object v6, v0, Llyiahf/vczjk/vx0;->OooO0OO:Llyiahf/vczjk/zb0;

    if-eqz v3, :cond_26

    invoke-virtual {v11, v3, v8}, Llyiahf/vczjk/gy0;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/vx0;)Llyiahf/vczjk/by0;

    move-result-object v2

    instance-of v3, v2, Llyiahf/vczjk/h82;

    if-eqz v3, :cond_23

    check-cast v2, Llyiahf/vczjk/h82;

    goto :goto_14

    :cond_23
    move-object v2, v8

    :goto_14
    if-nez v2, :cond_24

    goto/16 :goto_18

    :cond_24
    invoke-virtual {v5}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/h82;->o00ooo()Llyiahf/vczjk/e82;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/r82;->OooOOO0()Ljava/util/Set;

    move-result-object v5

    invoke-interface {v5, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_25

    goto/16 :goto_18

    :cond_25
    iget-object v2, v2, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    move-object/from16 v16, v6

    :goto_15
    move-object v13, v2

    goto :goto_17

    :cond_26
    iget-object v3, v5, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v2, v2, Llyiahf/vczjk/s72;->OooO0o:Llyiahf/vczjk/lh6;

    invoke-static {v2, v3}, Llyiahf/vczjk/kh6;->Oooo0oO(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Ljava/util/ArrayList;

    move-result-object v2

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_27
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_28

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v7, v3

    check-cast v7, Llyiahf/vczjk/hh6;

    instance-of v9, v7, Llyiahf/vczjk/hk0;

    if-eqz v9, :cond_29

    check-cast v7, Llyiahf/vczjk/hk0;

    invoke-virtual {v5}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v9

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v7}, Llyiahf/vczjk/hk0;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/r82;

    invoke-virtual {v7}, Llyiahf/vczjk/r82;->OooOOO0()Ljava/util/Set;

    move-result-object v7

    invoke-interface {v7, v9}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_27

    goto :goto_16

    :cond_28
    move-object v3, v8

    :cond_29
    :goto_16
    move-object v13, v3

    check-cast v13, Llyiahf/vczjk/hh6;

    if-nez v13, :cond_2a

    goto :goto_18

    :cond_2a
    new-instance v15, Llyiahf/vczjk/h87;

    invoke-virtual {v4}, Llyiahf/vczjk/zb7;->o000OOo()Llyiahf/vczjk/nd7;

    move-result-object v2

    const-string v3, "getTypeTable(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v15, v2}, Llyiahf/vczjk/h87;-><init>(Llyiahf/vczjk/nd7;)V

    sget-object v2, Llyiahf/vczjk/xea;->OooO0O0:Llyiahf/vczjk/xea;

    invoke-virtual {v4}, Llyiahf/vczjk/zb7;->o000000()Llyiahf/vczjk/ud7;

    move-result-object v2

    const-string v3, "getVersionRequirementTable(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/dl6;->OooO0O0(Llyiahf/vczjk/ud7;)Llyiahf/vczjk/xea;

    move-result-object v16

    const/16 v18, 0x0

    iget-object v12, v11, Llyiahf/vczjk/gy0;->OooO00o:Llyiahf/vczjk/s72;

    move-object/from16 v17, v6

    invoke-virtual/range {v12 .. v18}, Llyiahf/vczjk/s72;->OooO00o(Llyiahf/vczjk/hh6;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/xea;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ce4;)Llyiahf/vczjk/u72;

    move-result-object v2

    move-object/from16 v16, v17

    goto :goto_15

    :goto_17
    new-instance v12, Llyiahf/vczjk/h82;

    iget-object v0, v0, Llyiahf/vczjk/vx0;->OooO0Oo:Llyiahf/vczjk/sx8;

    move-object/from16 v17, v0

    move-object v15, v14

    move-object v14, v4

    invoke-direct/range {v12 .. v17}, Llyiahf/vczjk/h82;-><init>(Llyiahf/vczjk/u72;Llyiahf/vczjk/zb7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/zb0;Llyiahf/vczjk/sx8;)V

    move-object v8, v12

    :goto_18
    return-object v8

    :pswitch_14
    check-cast v0, Llyiahf/vczjk/lm7;

    const-string v2, "m"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/yx0;

    iget-object v2, v11, Llyiahf/vczjk/yx0;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    if-eqz v2, :cond_35

    invoke-virtual {v0}, Llyiahf/vczjk/lm7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v2

    check-cast v2, Ljava/lang/reflect/Method;

    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v2

    const-string v3, "getDeclaringClass(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/lang/Class;->isInterface()Z

    move-result v2

    if-eqz v2, :cond_34

    invoke-virtual {v0}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    move-result v3

    const v4, -0x69e9ad94

    if-eq v3, v4, :cond_32

    const v4, -0x4d378041

    if-eq v3, v4, :cond_2c

    const v4, 0x8cdac1b

    if-eq v3, v4, :cond_2b

    goto :goto_1a

    :cond_2b
    const-string v3, "hashCode"

    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_33

    goto :goto_1a

    :cond_2c
    const-string v3, "equals"

    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_2d

    goto :goto_1a

    :cond_2d
    invoke-virtual {v0}, Llyiahf/vczjk/lm7;->OooO0oO()Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o00000oO(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rm7;

    if-eqz v0, :cond_2e

    iget-object v0, v0, Llyiahf/vczjk/rm7;->OooO00o:Llyiahf/vczjk/pm7;

    goto :goto_19

    :cond_2e
    move-object v0, v8

    :goto_19
    instance-of v2, v0, Llyiahf/vczjk/em7;

    if-eqz v2, :cond_2f

    move-object v8, v0

    check-cast v8, Llyiahf/vczjk/em7;

    :cond_2f
    if-nez v8, :cond_30

    goto :goto_1a

    :cond_30
    iget-object v0, v8, Llyiahf/vczjk/em7;->OooO0O0:Llyiahf/vczjk/gm7;

    instance-of v2, v0, Llyiahf/vczjk/cm7;

    if-eqz v2, :cond_31

    check-cast v0, Llyiahf/vczjk/cm7;

    invoke-virtual {v0}, Llyiahf/vczjk/cm7;->OooO0OO()Llyiahf/vczjk/hc3;

    move-result-object v0

    if-eqz v0, :cond_31

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const-string v2, "java.lang.Object"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_31

    move v0, v9

    goto :goto_1b

    :cond_31
    :goto_1a
    const/4 v0, 0x0

    goto :goto_1b

    :cond_32
    const-string v3, "toString"

    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_31

    :cond_33
    invoke-virtual {v0}, Llyiahf/vczjk/lm7;->OooO0oO()Ljava/util/List;

    move-result-object v0

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    :goto_1b
    if-eqz v0, :cond_34

    move v0, v9

    goto :goto_1c

    :cond_34
    const/4 v0, 0x0

    :goto_1c
    if-nez v0, :cond_35

    move v6, v9

    goto :goto_1d

    :cond_35
    const/4 v6, 0x0

    :goto_1d
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_15
    check-cast v0, Llyiahf/vczjk/eo0;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/ty8;->OooO:Ljava/util/LinkedHashMap;

    check-cast v11, Llyiahf/vczjk/ho8;

    invoke-static {v11}, Llyiahf/vczjk/r02;->OooOO0O(Llyiahf/vczjk/co0;)Ljava/lang/String;

    move-result-object v2

    invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_16
    check-cast v0, Llyiahf/vczjk/o0;

    const-string v2, "supertypes"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/o0O00000;

    invoke-virtual {v11}, Llyiahf/vczjk/o0O00000;->OooO0oo()Llyiahf/vczjk/sp3;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "superTypes"

    iget-object v3, v0, Llyiahf/vczjk/o0;->OooO00o:Ljava/util/Collection;

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_38

    invoke-virtual {v11}, Llyiahf/vczjk/o0O00000;->OooO0oO()Llyiahf/vczjk/uk4;

    move-result-object v2

    if-eqz v2, :cond_36

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    goto :goto_1e

    :cond_36
    move-object v2, v8

    :goto_1e
    if-nez v2, :cond_37

    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_37
    move-object v3, v2

    :cond_38
    nop

    instance-of v2, v3, Ljava/util/List;

    if-eqz v2, :cond_39

    move-object v8, v3

    check-cast v8, Ljava/util/List;

    :cond_39
    if-nez v8, :cond_3a

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v3}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v8

    :cond_3a
    invoke-virtual {v11, v8}, Llyiahf/vczjk/o0O00000;->OooOO0o(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    const-string v3, "<set-?>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v2, v0, Llyiahf/vczjk/o0;->OooO0O0:Ljava/util/List;

    return-object v7

    :pswitch_17
    check-cast v0, Llyiahf/vczjk/iaa;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v2

    if-nez v2, :cond_3b

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v2, v0, Llyiahf/vczjk/t4a;

    if-eqz v2, :cond_3b

    check-cast v0, Llyiahf/vczjk/t4a;

    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    check-cast v11, Llyiahf/vczjk/v82;

    invoke-static {v0, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3b

    move v6, v9

    goto :goto_1f

    :cond_3b
    const/4 v6, 0x0

    :goto_1f
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_18
    sget-object v2, Llyiahf/vczjk/uk2;->OooOo0:Llyiahf/vczjk/uk2;

    check-cast v0, Llyiahf/vczjk/o0O00o0;

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/bv0;

    iget-boolean v3, v11, Llyiahf/vczjk/bv0;->OooO0O0:Z

    iget-object v4, v0, Llyiahf/vczjk/o0O00o0;->OooO00o:Llyiahf/vczjk/yk4;

    if-eqz v3, :cond_3c

    if-eqz v4, :cond_3c

    invoke-static {v4}, Llyiahf/vczjk/m6a;->o0ooOO0(Llyiahf/vczjk/yk4;)Z

    move-result v3

    if-ne v3, v9, :cond_3c

    goto/16 :goto_22

    :cond_3c
    if-eqz v4, :cond_40

    invoke-virtual {v2, v4}, Llyiahf/vczjk/uk2;->Ooooooo(Llyiahf/vczjk/yk4;)Llyiahf/vczjk/n3a;

    move-result-object v3

    if-eqz v3, :cond_40

    invoke-static {v3}, Llyiahf/vczjk/m6a;->OoooOO0(Llyiahf/vczjk/o3a;)Ljava/util/List;

    move-result-object v3

    const-string v6, "$receiver"

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v6, v4, Llyiahf/vczjk/uk4;

    if-eqz v6, :cond_3f

    check-cast v4, Llyiahf/vczjk/uk4;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v4

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    new-instance v9, Ljava/util/ArrayList;

    invoke-static {v3, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-static {v4, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    move-result v3

    invoke-direct {v9, v3}, Ljava/util/ArrayList;-><init>(I)V

    :goto_20
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3e

    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3e

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/z4a;

    check-cast v3, Llyiahf/vczjk/t4a;

    invoke-static {v2, v4}, Llyiahf/vczjk/m6a;->OoooOOo(Llyiahf/vczjk/fz0;Llyiahf/vczjk/z4a;)Llyiahf/vczjk/iaa;

    move-result-object v4

    iget-object v5, v0, Llyiahf/vczjk/o0O00o0;->OooO0O0:Llyiahf/vczjk/g74;

    if-nez v4, :cond_3d

    new-instance v4, Llyiahf/vczjk/o0O00o0;

    invoke-direct {v4, v8, v5, v3}, Llyiahf/vczjk/o0O00o0;-><init>(Llyiahf/vczjk/yk4;Llyiahf/vczjk/g74;Llyiahf/vczjk/t4a;)V

    goto :goto_21

    :cond_3d
    new-instance v10, Llyiahf/vczjk/o0O00o0;

    iget-object v12, v11, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/ld9;

    iget-object v12, v12, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/s64;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v13

    iget-object v12, v12, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v12, v5, v13}, Llyiahf/vczjk/eo;->OooO0O0(Llyiahf/vczjk/g74;Llyiahf/vczjk/ko;)Llyiahf/vczjk/g74;

    move-result-object v5

    invoke-direct {v10, v4, v5, v3}, Llyiahf/vczjk/o0O00o0;-><init>(Llyiahf/vczjk/yk4;Llyiahf/vczjk/g74;Llyiahf/vczjk/t4a;)V

    move-object v4, v10

    :goto_21
    invoke-virtual {v9, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_20

    :cond_3e
    move-object v8, v9

    goto :goto_22

    :cond_3f
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "ClassicTypeSystemContext couldn\'t handle: "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ", "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-static {v3, v2, v0}, Llyiahf/vczjk/ix8;->OooOO0o(Llyiahf/vczjk/zm7;Ljava/lang/Class;Ljava/lang/StringBuilder;)Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_40
    :goto_22
    return-object v8

    :pswitch_19
    check-cast v0, Llyiahf/vczjk/hc3;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/pd4;

    invoke-virtual {v11, v0}, Llyiahf/vczjk/pd4;->OooO0OO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hk0;

    move-result-object v0

    if-eqz v0, :cond_42

    iget-object v2, v11, Llyiahf/vczjk/pd4;->OooO0OO:Llyiahf/vczjk/s72;

    if-eqz v2, :cond_41

    invoke-virtual {v0, v2}, Llyiahf/vczjk/hk0;->o0000O0O(Llyiahf/vczjk/s72;)V

    move-object v8, v0

    goto :goto_23

    :cond_41
    const-string v0, "components"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v8

    :cond_42
    :goto_23
    return-object v8

    :pswitch_1a
    check-cast v0, Llyiahf/vczjk/al4;

    check-cast v11, Llyiahf/vczjk/o0OO00O;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "descriptor"

    iget-object v2, v11, Llyiahf/vczjk/o0OO00O;->OooOOO:Llyiahf/vczjk/oo0o0Oo;

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v2, Llyiahf/vczjk/oo0o0Oo;->OooOOO:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dp8;

    return-object v0

    :pswitch_1b
    check-cast v0, Llyiahf/vczjk/tm7;

    const-string v2, "kotlinClass"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/lr;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Ljava/util/HashMap;

    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    new-instance v3, Ljava/util/HashMap;

    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    new-instance v5, Ljava/util/HashMap;

    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    new-instance v7, Llyiahf/vczjk/era;

    invoke-direct {v7, v2, v11, v3}, Llyiahf/vczjk/era;-><init>(Ljava/io/Serializable;Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    const-string v8, "klass"

    invoke-static {v0, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v8

    :goto_24
    invoke-virtual {v8}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v10

    const-string v11, "toString(...)"

    const-string v12, "("

    if-eqz v10, :cond_49

    invoke-virtual {v8}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/reflect/Method;

    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v13

    new-instance v14, Ljava/lang/StringBuilder;

    invoke-direct {v14, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v12

    invoke-static {v12}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v12

    :goto_25
    invoke-virtual {v12}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_43

    invoke-virtual {v12}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Ljava/lang/Class;

    invoke-static {v15}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v15}, Llyiahf/vczjk/rl7;->OooO0O0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v14, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_25

    :cond_43
    const-string v12, ")"

    invoke-virtual {v14, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v12

    const-string v15, "getReturnType(...)"

    invoke-static {v12, v15}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v12}, Llyiahf/vczjk/rl7;->OooO0O0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v12

    invoke-virtual {v14, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v12

    invoke-static {v12, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7, v13, v12}, Llyiahf/vczjk/era;->OoooOoo(Llyiahf/vczjk/qt5;Ljava/lang/String;)Llyiahf/vczjk/ld9;

    move-result-object v11

    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v12

    invoke-static {v12}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v12

    :goto_26
    invoke-virtual {v12}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_45

    invoke-virtual {v12}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/annotation/Annotation;

    invoke-static {v13}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v13}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v14

    invoke-static {v14}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v14

    invoke-static {v14}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v15

    new-instance v6, Llyiahf/vczjk/ql7;

    invoke-direct {v6, v13}, Llyiahf/vczjk/ql7;-><init>(Ljava/lang/annotation/Annotation;)V

    move/from16 v17, v9

    iget-object v9, v11, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/era;

    iget-object v9, v9, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/lr;

    move-object/from16 v18, v0

    iget-object v0, v11, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v9, v15, v6, v0}, Llyiahf/vczjk/lr;->OooOo(Llyiahf/vczjk/hy0;Llyiahf/vczjk/ql7;Ljava/util/List;)Llyiahf/vczjk/ex9;

    move-result-object v0

    if-eqz v0, :cond_44

    invoke-static {v0, v13, v14}, Llyiahf/vczjk/vl6;->OooOoo(Llyiahf/vczjk/nk4;Ljava/lang/annotation/Annotation;Ljava/lang/Class;)V

    :cond_44
    move/from16 v9, v17

    move-object/from16 v0, v18

    goto :goto_26

    :cond_45
    move-object/from16 v18, v0

    move/from16 v17, v9

    invoke-virtual {v10}, Ljava/lang/reflect/Method;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    move-result-object v0

    const-string v6, "getParameterAnnotations(...)"

    invoke-static {v0, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, [[Ljava/lang/annotation/Annotation;

    array-length v6, v0

    const/4 v9, 0x0

    :goto_27
    if-ge v9, v6, :cond_48

    aget-object v10, v0, v9

    invoke-static {v10}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v10

    :cond_46
    :goto_28
    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v12

    if-eqz v12, :cond_47

    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Ljava/lang/annotation/Annotation;

    invoke-static {v12}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v14

    new-instance v15, Llyiahf/vczjk/ql7;

    invoke-direct {v15, v12}, Llyiahf/vczjk/ql7;-><init>(Ljava/lang/annotation/Annotation;)V

    invoke-virtual {v11, v9, v14, v15}, Llyiahf/vczjk/ld9;->o0OoOo0(ILlyiahf/vczjk/hy0;Llyiahf/vczjk/ql7;)Llyiahf/vczjk/ex9;

    move-result-object v14

    if-eqz v14, :cond_46

    invoke-static {v14, v12, v13}, Llyiahf/vczjk/vl6;->OooOoo(Llyiahf/vczjk/nk4;Ljava/lang/annotation/Annotation;Ljava/lang/Class;)V

    goto :goto_28

    :cond_47
    add-int/lit8 v9, v9, 0x1

    goto :goto_27

    :cond_48
    invoke-virtual {v11}, Llyiahf/vczjk/ld9;->OooOOOO()V

    move/from16 v9, v17

    move-object/from16 v0, v18

    goto/16 :goto_24

    :cond_49
    move-object/from16 v18, v0

    move/from16 v17, v9

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Class;->getDeclaredConstructors()[Ljava/lang/reflect/Constructor;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v0

    :goto_29
    invoke-virtual {v0}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_51

    invoke-virtual {v0}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/reflect/Constructor;

    sget-object v8, Llyiahf/vczjk/vy8;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v10

    :goto_2a
    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_4a

    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/Class;

    invoke-static {v13}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v13}, Llyiahf/vczjk/rl7;->OooO0O0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v9, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_2a

    :cond_4a
    const-string v10, ")V"

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7, v8, v9}, Llyiahf/vczjk/era;->OoooOoo(Llyiahf/vczjk/qt5;Ljava/lang/String;)Llyiahf/vczjk/ld9;

    move-result-object v8

    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v9

    :goto_2b
    invoke-virtual {v9}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_4c

    invoke-virtual {v9}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/annotation/Annotation;

    invoke-static {v10}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v10}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v14

    new-instance v15, Llyiahf/vczjk/ql7;

    invoke-direct {v15, v10}, Llyiahf/vczjk/ql7;-><init>(Ljava/lang/annotation/Annotation;)V

    move-object/from16 p1, v0

    iget-object v0, v8, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/era;

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/lr;

    iget-object v1, v8, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v0, v14, v15, v1}, Llyiahf/vczjk/lr;->OooOo(Llyiahf/vczjk/hy0;Llyiahf/vczjk/ql7;Ljava/util/List;)Llyiahf/vczjk/ex9;

    move-result-object v0

    if-eqz v0, :cond_4b

    invoke-static {v0, v10, v13}, Llyiahf/vczjk/vl6;->OooOoo(Llyiahf/vczjk/nk4;Ljava/lang/annotation/Annotation;Ljava/lang/Class;)V

    :cond_4b
    move-object/from16 v1, p0

    move-object/from16 v0, p1

    goto :goto_2b

    :cond_4c
    move-object/from16 p1, v0

    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    array-length v1, v0

    if-nez v1, :cond_4d

    goto :goto_2e

    :cond_4d
    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v1

    array-length v1, v1

    array-length v6, v0

    sub-int/2addr v1, v6

    array-length v6, v0

    const/4 v9, 0x0

    :goto_2c
    if-ge v9, v6, :cond_50

    aget-object v10, v0, v9

    invoke-static {v10}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v10

    :goto_2d
    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_4f

    invoke-virtual {v10}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/annotation/Annotation;

    invoke-static {v13}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v14

    invoke-static {v14}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v14

    add-int v15, v9, v1

    move-object/from16 v19, v0

    invoke-static {v14}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    move/from16 v20, v1

    new-instance v1, Llyiahf/vczjk/ql7;

    invoke-direct {v1, v13}, Llyiahf/vczjk/ql7;-><init>(Ljava/lang/annotation/Annotation;)V

    invoke-virtual {v8, v15, v0, v1}, Llyiahf/vczjk/ld9;->o0OoOo0(ILlyiahf/vczjk/hy0;Llyiahf/vczjk/ql7;)Llyiahf/vczjk/ex9;

    move-result-object v0

    if-eqz v0, :cond_4e

    invoke-static {v0, v13, v14}, Llyiahf/vczjk/vl6;->OooOoo(Llyiahf/vczjk/nk4;Ljava/lang/annotation/Annotation;Ljava/lang/Class;)V

    :cond_4e
    move-object/from16 v0, v19

    move/from16 v1, v20

    goto :goto_2d

    :cond_4f
    move-object/from16 v19, v0

    move/from16 v20, v1

    add-int/lit8 v9, v9, 0x1

    goto :goto_2c

    :cond_50
    :goto_2e
    invoke-virtual {v8}, Llyiahf/vczjk/ld9;->OooOOOO()V

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    goto/16 :goto_29

    :cond_51
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v0

    :cond_52
    :goto_2f
    invoke-virtual {v0}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_55

    invoke-virtual {v0}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/reflect/Field;

    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    move-result-object v8

    invoke-static {v8, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/rl7;->OooO0O0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v8

    const-string v9, "desc"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v6}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v6

    const-string v9, "asString(...)"

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v9, Llyiahf/vczjk/lg5;

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v6, 0x23

    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-direct {v9, v6}, Llyiahf/vczjk/lg5;-><init>(Ljava/lang/String;)V

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/lang/reflect/Field;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v1

    :cond_53
    :goto_30
    invoke-virtual {v1}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_54

    invoke-virtual {v1}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/annotation/Annotation;

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v8}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v11

    new-instance v12, Llyiahf/vczjk/ql7;

    invoke-direct {v12, v8}, Llyiahf/vczjk/ql7;-><init>(Ljava/lang/annotation/Annotation;)V

    iget-object v13, v7, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/lr;

    invoke-virtual {v13, v11, v12, v6}, Llyiahf/vczjk/lr;->OooOo(Llyiahf/vczjk/hy0;Llyiahf/vczjk/ql7;Ljava/util/List;)Llyiahf/vczjk/ex9;

    move-result-object v11

    if-eqz v11, :cond_53

    invoke-static {v11, v8, v10}, Llyiahf/vczjk/vl6;->OooOoo(Llyiahf/vczjk/nk4;Ljava/lang/annotation/Annotation;Ljava/lang/Class;)V

    goto :goto_30

    :cond_54
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_52

    iget-object v1, v7, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/HashMap;

    invoke-virtual {v1, v9, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto/16 :goto_2f

    :cond_55
    new-instance v0, Llyiahf/vczjk/mo;

    invoke-direct {v0, v2, v3, v5}, Llyiahf/vczjk/mo;-><init>(Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
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
