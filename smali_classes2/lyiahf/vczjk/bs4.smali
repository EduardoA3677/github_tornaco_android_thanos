.class public final Llyiahf/vczjk/bs4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ds4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ds4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bs4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bs4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    const/4 v1, 0x3

    const/4 v2, 0x0

    const/4 v3, 0x2

    const/4 v4, 0x1

    iget-object v5, v0, Llyiahf/vczjk/bs4;->OooOOO:Llyiahf/vczjk/ds4;

    const-string v6, "name"

    iget v7, v0, Llyiahf/vczjk/bs4;->OooOOO0:I

    packed-switch v7, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/qt5;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iget-object v3, v5, Llyiahf/vczjk/ds4;->OooO0oO:Llyiahf/vczjk/r60;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    invoke-virtual {v5, v2, v1}, Llyiahf/vczjk/ds4;->OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v5}, Llyiahf/vczjk/ds4;->OooOOo0()Llyiahf/vczjk/v02;

    move-result-object v1

    sget v3, Llyiahf/vczjk/n72;->OooO00o:I

    sget-object v3, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    invoke-static {v1, v3}, Llyiahf/vczjk/n72;->OooOOO(Llyiahf/vczjk/v02;Llyiahf/vczjk/ly0;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    goto :goto_0

    :cond_0
    iget-object v1, v5, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v3, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s64;

    iget-object v3, v3, Llyiahf/vczjk/s64;->OooOOo:Llyiahf/vczjk/tp3;

    invoke-virtual {v3, v1, v2}, Llyiahf/vczjk/tp3;->OooOOO0(Llyiahf/vczjk/ld9;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    :goto_0
    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/qt5;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/LinkedHashSet;

    iget-object v6, v5, Llyiahf/vczjk/ds4;->OooO0o:Llyiahf/vczjk/l45;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/Collection;

    invoke-direct {v2, v6}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    new-instance v6, Ljava/util/LinkedHashMap;

    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_2

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/ho8;

    invoke-static {v9, v3}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v9

    invoke-virtual {v6, v9}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    if-nez v10, :cond_1

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v6, v9, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    check-cast v10, Ljava/util/List;

    invoke-interface {v10, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    invoke-virtual {v6}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_3
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v7

    if-eq v7, v4, :cond_3

    sget-object v7, Llyiahf/vczjk/g13;->OooOoO0:Llyiahf/vczjk/g13;

    invoke-static {v6, v7}, Llyiahf/vczjk/bua;->Oooo0oO(Ljava/util/Collection;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object v7

    invoke-interface {v2, v6}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    invoke-interface {v2, v7}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    goto :goto_2

    :cond_4
    invoke-virtual {v5, v2, v1}, Llyiahf/vczjk/ds4;->OooOOO0(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;)V

    iget-object v1, v5, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v3, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s64;

    iget-object v3, v3, Llyiahf/vczjk/s64;->OooOOo:Llyiahf/vczjk/tp3;

    invoke-virtual {v3, v1, v2}, Llyiahf/vczjk/tp3;->OooOOO0(Llyiahf/vczjk/ld9;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    return-object v1

    :pswitch_1
    move-object/from16 v7, p1

    check-cast v7, Llyiahf/vczjk/qt5;

    invoke-static {v7, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v6, v5, Llyiahf/vczjk/ds4;->OooO0OO:Llyiahf/vczjk/rr4;

    if-eqz v6, :cond_5

    iget-object v1, v6, Llyiahf/vczjk/ds4;->OooO0oO:Llyiahf/vczjk/r60;

    invoke-virtual {v1, v7}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sa7;

    goto/16 :goto_c

    :cond_5
    iget-object v6, v5, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v6}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/c12;

    invoke-interface {v6, v7}, Llyiahf/vczjk/c12;->OooO0o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/im7;

    move-result-object v6

    const/4 v7, 0x0

    if-eqz v6, :cond_16

    iget-object v8, v6, Llyiahf/vczjk/im7;->OooO00o:Ljava/lang/reflect/Field;

    invoke-virtual {v8}, Ljava/lang/reflect/Field;->isEnumConstant()Z

    move-result v9

    if-nez v9, :cond_16

    new-instance v9, Llyiahf/vczjk/hl7;

    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v6}, Llyiahf/vczjk/im7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v10

    check-cast v10, Ljava/lang/reflect/Field;

    invoke-virtual {v10}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v10

    invoke-static {v10}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v10

    xor-int/lit8 v14, v10, 0x1

    iget-object v10, v5, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    invoke-static {v10, v6}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v12

    invoke-virtual {v5}, Llyiahf/vczjk/ds4;->OooOOo0()Llyiahf/vczjk/v02;

    move-result-object v11

    sget-object v13, Llyiahf/vczjk/yk5;->OooOOO0:Llyiahf/vczjk/wp3;

    invoke-virtual {v6}, Llyiahf/vczjk/km7;->OooO0o0()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/ht6;->OooOoOO(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v13

    invoke-virtual {v6}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v15

    move/from16 v18, v3

    iget-object v3, v10, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s64;

    move/from16 v19, v4

    iget-object v4, v3, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v16

    invoke-virtual {v6}, Llyiahf/vczjk/im7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Field;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v4

    if-eqz v4, :cond_6

    invoke-virtual {v6}, Llyiahf/vczjk/im7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Field;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v4

    if-eqz v4, :cond_6

    move/from16 v17, v19

    goto :goto_3

    :cond_6
    move/from16 v17, v2

    :goto_3
    invoke-static/range {v11 .. v17}, Llyiahf/vczjk/r64;->o0000Oo0(Llyiahf/vczjk/v02;Llyiahf/vczjk/lr4;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/hz7;Z)Llyiahf/vczjk/r64;

    move-result-object v4

    iput-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v4, v7, v7, v7, v7}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    invoke-virtual {v8}, Ljava/lang/reflect/Field;->getGenericType()Ljava/lang/reflect/Type;

    move-result-object v4

    const-string v8, "getGenericType(...)"

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v8, v4, Ljava/lang/Class;

    if-eqz v8, :cond_7

    move-object v11, v4

    check-cast v11, Ljava/lang/Class;

    invoke-virtual {v11}, Ljava/lang/Class;->isPrimitive()Z

    move-result v12

    if-eqz v12, :cond_7

    new-instance v4, Llyiahf/vczjk/nm7;

    invoke-direct {v4, v11}, Llyiahf/vczjk/nm7;-><init>(Ljava/lang/Class;)V

    goto :goto_6

    :cond_7
    instance-of v11, v4, Ljava/lang/reflect/GenericArrayType;

    if-nez v11, :cond_a

    if-eqz v8, :cond_8

    move-object v8, v4

    check-cast v8, Ljava/lang/Class;

    invoke-virtual {v8}, Ljava/lang/Class;->isArray()Z

    move-result v8

    if-eqz v8, :cond_8

    goto :goto_5

    :cond_8
    instance-of v8, v4, Ljava/lang/reflect/WildcardType;

    if-eqz v8, :cond_9

    new-instance v8, Llyiahf/vczjk/sm7;

    check-cast v4, Ljava/lang/reflect/WildcardType;

    invoke-direct {v8, v4}, Llyiahf/vczjk/sm7;-><init>(Ljava/lang/reflect/WildcardType;)V

    :goto_4
    move-object v4, v8

    goto :goto_6

    :cond_9
    new-instance v8, Llyiahf/vczjk/em7;

    invoke-direct {v8, v4}, Llyiahf/vczjk/em7;-><init>(Ljava/lang/reflect/Type;)V

    goto :goto_4

    :cond_a
    :goto_5
    new-instance v8, Llyiahf/vczjk/wl7;

    invoke-direct {v8, v4}, Llyiahf/vczjk/wl7;-><init>(Ljava/lang/reflect/Type;)V

    goto :goto_4

    :goto_6
    sget-object v8, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v11, 0x7

    invoke-static {v8, v2, v7, v11}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v8

    iget-object v11, v10, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/uqa;

    invoke-virtual {v11, v4, v8}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/hk4;->Oooo00O(Llyiahf/vczjk/uk4;)Z

    move-result v4

    if-nez v4, :cond_b

    invoke-static {v13}, Llyiahf/vczjk/hk4;->Oooo00o(Llyiahf/vczjk/uk4;)Z

    move-result v4

    if-eqz v4, :cond_c

    :cond_b
    invoke-virtual {v6}, Llyiahf/vczjk/im7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Field;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v4

    if-eqz v4, :cond_c

    invoke-virtual {v6}, Llyiahf/vczjk/im7;->OooO0O0()Ljava/lang/reflect/Member;

    move-result-object v4

    check-cast v4, Ljava/lang/reflect/Field;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v4

    :cond_c
    iget-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    move-object v12, v4

    check-cast v12, Llyiahf/vczjk/ua7;

    sget-object v14, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-virtual {v5}, Llyiahf/vczjk/ds4;->OooOOOo()Llyiahf/vczjk/mp4;

    move-result-object v15

    const/16 v16, 0x0

    move-object/from16 v17, v14

    invoke-virtual/range {v12 .. v17}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    invoke-virtual {v5}, Llyiahf/vczjk/ds4;->OooOOo0()Llyiahf/vczjk/v02;

    move-result-object v4

    instance-of v8, v4, Llyiahf/vczjk/by0;

    if-eqz v8, :cond_d

    check-cast v4, Llyiahf/vczjk/by0;

    goto :goto_7

    :cond_d
    move-object v4, v7

    :goto_7
    if-eqz v4, :cond_e

    iget-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ua7;

    iget-object v8, v3, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v8, Llyiahf/vczjk/up3;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v8, "propertyDescriptor"

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v8, "c"

    invoke-static {v10, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :cond_e
    iget-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/ada;

    check-cast v4, Llyiahf/vczjk/ua7;

    invoke-virtual {v4}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v4

    if-eqz v8, :cond_15

    if-eqz v4, :cond_14

    sget v10, Llyiahf/vczjk/n72;->OooO00o:I

    invoke-interface {v8}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result v10

    if-nez v10, :cond_12

    invoke-static {v4}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v10

    if-eqz v10, :cond_f

    goto :goto_9

    :cond_f
    invoke-static {v4}, Llyiahf/vczjk/l5a;->OooO0O0(Llyiahf/vczjk/uk4;)Z

    move-result v10

    if-eqz v10, :cond_10

    goto :goto_8

    :cond_10
    invoke-static {v8}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v8

    invoke-static {v4}, Llyiahf/vczjk/hk4;->Oooo00O(Llyiahf/vczjk/uk4;)Z

    move-result v10

    if-nez v10, :cond_11

    sget-object v10, Llyiahf/vczjk/wk4;->OooO00o:Llyiahf/vczjk/v06;

    invoke-virtual {v8}, Llyiahf/vczjk/hk4;->OooOo0O()Llyiahf/vczjk/dp8;

    move-result-object v11

    invoke-virtual {v10, v11, v4}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v11

    if-nez v11, :cond_11

    const-string v11, "Number"

    invoke-virtual {v8, v11}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object v11

    invoke-interface {v11}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v11

    invoke-virtual {v10, v11, v4}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v11

    if-nez v11, :cond_11

    invoke-virtual {v8}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v8

    invoke-virtual {v10, v8, v4}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v8

    if-nez v8, :cond_11

    invoke-static {v4}, Llyiahf/vczjk/aaa;->OooO00o(Llyiahf/vczjk/uk4;)Z

    move-result v4

    if-eqz v4, :cond_12

    :cond_11
    :goto_8
    iget-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ua7;

    new-instance v8, Llyiahf/vczjk/o0O0000O;

    invoke-direct {v8, v5, v6, v1, v9}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v4, v7, v8}, Llyiahf/vczjk/ua7;->o0000OO(Llyiahf/vczjk/n45;Llyiahf/vczjk/le3;)V

    :cond_12
    :goto_9
    iget-object v4, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/sa7;

    iget-object v3, v3, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v4, :cond_13

    iget-object v1, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sa7;

    goto :goto_c

    :cond_13
    const/4 v3, 0x6

    new-array v1, v1, [Ljava/lang/Object;

    packed-switch v3, :pswitch_data_1

    const-string v4, "fqName"

    aput-object v4, v1, v2

    goto :goto_a

    :pswitch_2
    const-string v4, "javaClass"

    aput-object v4, v1, v2

    goto :goto_a

    :pswitch_3
    const-string v4, "field"

    aput-object v4, v1, v2

    goto :goto_a

    :pswitch_4
    const-string v4, "element"

    aput-object v4, v1, v2

    goto :goto_a

    :pswitch_5
    const-string v4, "descriptor"

    aput-object v4, v1, v2

    goto :goto_a

    :pswitch_6
    const-string v4, "member"

    aput-object v4, v1, v2

    :goto_a
    const-string v2, "kotlin/reflect/jvm/internal/impl/load/java/components/JavaResolverCache$1"

    aput-object v2, v1, v19

    packed-switch v3, :pswitch_data_2

    const-string v2, "getClassResolvedFromSource"

    aput-object v2, v1, v18

    goto :goto_b

    :pswitch_7
    const-string v2, "recordClass"

    aput-object v2, v1, v18

    goto :goto_b

    :pswitch_8
    const-string v2, "recordField"

    aput-object v2, v1, v18

    goto :goto_b

    :pswitch_9
    const-string v2, "recordConstructor"

    aput-object v2, v1, v18

    goto :goto_b

    :pswitch_a
    const-string v2, "recordMethod"

    aput-object v2, v1, v18

    :goto_b
    const-string v2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/IllegalArgumentException;

    invoke-direct {v2, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_14
    const/16 v1, 0x42

    invoke-static {v1}, Llyiahf/vczjk/n72;->OooO00o(I)V

    throw v7

    :cond_15
    const/16 v1, 0x41

    invoke-static {v1}, Llyiahf/vczjk/n72;->OooO00o(I)V

    throw v7

    :cond_16
    move-object v1, v7

    :goto_c
    return-object v1

    :pswitch_b
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/qt5;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v5, Llyiahf/vczjk/ds4;->OooO0OO:Llyiahf/vczjk/rr4;

    if-eqz v2, :cond_17

    iget-object v2, v2, Llyiahf/vczjk/ds4;->OooO0o:Llyiahf/vczjk/l45;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Collection;

    goto :goto_e

    :cond_17
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iget-object v3, v5, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v3}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/c12;

    invoke-interface {v3, v1}, Llyiahf/vczjk/c12;->OooO0O0(Llyiahf/vczjk/qt5;)Ljava/util/Collection;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_18
    :goto_d
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_19

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/lm7;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ds4;->OooOo00(Llyiahf/vczjk/lm7;)Llyiahf/vczjk/o64;

    move-result-object v4

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ds4;->OooOOo(Llyiahf/vczjk/o64;)Z

    move-result v6

    if-eqz v6, :cond_18

    iget-object v6, v5, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v6, v6, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s64;

    iget-object v6, v6, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_d

    :cond_19
    invoke-virtual {v5, v2, v1}, Llyiahf/vczjk/ds4;->OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V

    move-object v1, v2

    :goto_e
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_1
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_5
        :pswitch_3
        :pswitch_5
        :pswitch_2
        :pswitch_5
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_a
        :pswitch_a
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_7
    .end packed-switch
.end method
