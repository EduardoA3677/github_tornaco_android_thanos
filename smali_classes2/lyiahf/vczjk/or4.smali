.class public final Llyiahf/vczjk/or4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ld9;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Llyiahf/vczjk/rr4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rr4;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/or4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/or4;->OooOOO:Llyiahf/vczjk/ld9;

    iput-object p2, p0, Llyiahf/vczjk/or4;->OooOOOO:Llyiahf/vczjk/rr4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/rr4;Llyiahf/vczjk/ld9;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/or4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/or4;->OooOOOO:Llyiahf/vczjk/rr4;

    iput-object p2, p0, Llyiahf/vczjk/or4;->OooOOO:Llyiahf/vczjk/ld9;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 27

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/or4;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v1, v0, Llyiahf/vczjk/or4;->OooOOO:Llyiahf/vczjk/ld9;

    iget-object v2, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v3, v0, Llyiahf/vczjk/or4;->OooOOOO:Llyiahf/vczjk/rr4;

    iget-object v3, v3, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v2, Llyiahf/vczjk/up3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "thisDescriptor"

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "c"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v1

    return-object v1

    :pswitch_0
    iget-object v2, v0, Llyiahf/vczjk/or4;->OooOOOO:Llyiahf/vczjk/rr4;

    iget-object v1, v2, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iget-object v1, v1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->getDeclaredConstructors()[Ljava/lang/reflect/Constructor;

    move-result-object v1

    const-string v3, "getDeclaredConstructors(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/xl7;->OooOOO:Llyiahf/vczjk/xl7;

    new-instance v4, Llyiahf/vczjk/e13;

    const/4 v9, 0x0

    invoke-direct {v4, v1, v9, v3}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    sget-object v1, Llyiahf/vczjk/yl7;->OooOOO:Llyiahf/vczjk/yl7;

    invoke-static {v4, v1}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v1

    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    const/4 v10, 0x1

    iget-object v11, v2, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v12, v2, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    if-eqz v4, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/fm7;

    invoke-static {v11, v4}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v5

    iget-object v6, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s64;

    iget-object v7, v6, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v7, v4}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v7

    invoke-static {v12, v5, v9, v7}, Llyiahf/vczjk/e64;->o0000oOo(Llyiahf/vczjk/by0;Llyiahf/vczjk/ko;ZLlyiahf/vczjk/hz7;)Llyiahf/vczjk/e64;

    move-result-object v5

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object v7

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    iget-object v8, v11, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    new-instance v13, Llyiahf/vczjk/rr0;

    invoke-direct {v13, v11, v5, v4, v7}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/x02;Llyiahf/vczjk/e74;I)V

    new-instance v7, Llyiahf/vczjk/ld9;

    invoke-direct {v7, v6, v13, v8}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    iget-object v6, v4, Llyiahf/vczjk/fm7;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    array-length v11, v8

    if-nez v11, :cond_0

    sget-object v6, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    goto :goto_1

    :cond_0
    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v11

    invoke-virtual {v11}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v13

    if-eqz v13, :cond_1

    invoke-virtual {v11}, Ljava/lang/Class;->getModifiers()I

    move-result v11

    invoke-static {v11}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v11

    if-nez v11, :cond_1

    array-length v11, v8

    invoke-static {v10, v11, v8}, Llyiahf/vczjk/sy;->o0ooOO0(II[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v8

    check-cast v8, [Ljava/lang/reflect/Type;

    :cond_1
    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    move-result-object v10

    array-length v11, v10

    array-length v13, v8

    if-lt v11, v13, :cond_4

    array-length v11, v10

    array-length v13, v8

    if-le v11, v13, :cond_2

    array-length v11, v10

    array-length v13, v8

    sub-int/2addr v11, v13

    array-length v13, v10

    invoke-static {v11, v13, v10}, Llyiahf/vczjk/sy;->o0ooOO0(II[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v10

    check-cast v10, [[Ljava/lang/annotation/Annotation;

    :cond_2
    invoke-virtual {v6}, Ljava/lang/reflect/Constructor;->isVarArgs()Z

    move-result v6

    invoke-virtual {v4, v8, v10, v6}, Llyiahf/vczjk/km7;->OooO0Oo([Ljava/lang/reflect/Type;[[Ljava/lang/annotation/Annotation;Z)Ljava/util/ArrayList;

    move-result-object v6

    :goto_1
    invoke-static {v7, v5, v6}, Llyiahf/vczjk/ds4;->OooOo0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/tf3;Ljava/util/List;)Llyiahf/vczjk/pc0;

    move-result-object v6

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooOo00()Ljava/util/List;

    move-result-object v8

    const-string v10, "getDeclaredTypeParameters(...)"

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4}, Llyiahf/vczjk/fm7;->OooOOO()Ljava/util/ArrayList;

    move-result-object v10

    new-instance v11, Ljava/util/ArrayList;

    const/16 v13, 0xa

    invoke-static {v10, v13}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-direct {v11, v13}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_3

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/qm7;

    iget-object v14, v7, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/v4a;

    invoke-interface {v14, v13}, Llyiahf/vczjk/v4a;->OooO0oO(Llyiahf/vczjk/qm7;)Llyiahf/vczjk/t4a;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_3
    invoke-static {v11, v8}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v8

    invoke-virtual {v4}, Llyiahf/vczjk/km7;->OooO0o0()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/ht6;->OooOoOO(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v4

    iget-object v10, v6, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v10, Ljava/util/List;

    invoke-virtual {v5, v10, v4, v8}, Llyiahf/vczjk/ux0;->o0000oO0(Ljava/util/List;Llyiahf/vczjk/q72;Ljava/util/List;)V

    invoke-virtual {v5, v9}, Llyiahf/vczjk/e64;->o0000Oo0(Z)V

    iget-boolean v4, v6, Llyiahf/vczjk/pc0;->OooOOO:Z

    invoke-virtual {v5, v4}, Llyiahf/vczjk/e64;->o0000Oo(Z)V

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v4

    invoke-virtual {v5, v4}, Llyiahf/vczjk/tf3;->o0000OoO(Llyiahf/vczjk/dp8;)V

    iget-object v4, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_0

    :cond_4
    new-instance v1, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Illegal generic signature: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_5
    iget-object v1, v2, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    invoke-virtual {v1}, Llyiahf/vczjk/cm7;->OooO0oO()Z

    move-result v4

    sget-object v5, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    const-string v6, "PROTECTED_AND_PACKAGE"

    const-string v7, "getVisibility(...)"

    const/4 v13, 0x0

    iget-object v14, v0, Llyiahf/vczjk/or4;->OooOOO:Llyiahf/vczjk/ld9;

    if-eqz v4, :cond_b

    iget-object v4, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v4

    invoke-static {v12, v5, v10, v4}, Llyiahf/vczjk/e64;->o0000oOo(Llyiahf/vczjk/by0;Llyiahf/vczjk/ko;ZLlyiahf/vczjk/hz7;)Llyiahf/vczjk/e64;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/cm7;->OooO0o()Ljava/util/ArrayList;

    move-result-object v15

    new-instance v10, Ljava/util/ArrayList;

    invoke-virtual {v15}, Ljava/util/ArrayList;->size()I

    move-result v8

    invoke-direct {v10, v8}, Ljava/util/ArrayList;-><init>(I)V

    sget-object v8, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v0, 0x6

    invoke-static {v8, v9, v13, v0}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v8

    invoke-virtual {v15}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    move/from16 v16, v9

    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_6

    add-int/lit8 v25, v16, 0x1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/om7;

    invoke-virtual {v15}, Llyiahf/vczjk/om7;->OooO0o()Llyiahf/vczjk/y64;

    move-result-object v13

    iget-object v9, v11, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/uqa;

    invoke-virtual {v9, v13, v8}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v19

    new-instance v13, Llyiahf/vczjk/tca;

    invoke-virtual {v15}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v18

    iget-object v9, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/s64;

    iget-object v9, v9, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v9, v15}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v24

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/4 v15, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v17, v5

    move-object v9, v14

    move-object v14, v4

    const/4 v4, 0x0

    invoke-direct/range {v13 .. v24}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object v13, v4

    move-object v4, v14

    move/from16 v16, v25

    move-object v14, v9

    const/4 v9, 0x0

    goto :goto_3

    :cond_6
    move-object/from16 v26, v14

    move-object v14, v4

    move-object v4, v13

    move v13, v9

    move-object/from16 v9, v26

    invoke-virtual {v14, v13}, Llyiahf/vczjk/e64;->o0000Oo(Z)V

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v0

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v8, Llyiahf/vczjk/j64;->OooO0O0:Llyiahf/vczjk/q72;

    invoke-virtual {v0, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_7

    sget-object v0, Llyiahf/vczjk/j64;->OooO0OO:Llyiahf/vczjk/q72;

    invoke-static {v0, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_7
    invoke-virtual {v14, v10, v0}, Llyiahf/vczjk/ux0;->o0000o(Ljava/util/List;Llyiahf/vczjk/q72;)V

    const/4 v13, 0x0

    invoke-virtual {v14, v13}, Llyiahf/vczjk/e64;->o0000Oo0(Z)V

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v14, v0}, Llyiahf/vczjk/tf3;->o0000OoO(Llyiahf/vczjk/dp8;)V

    const/4 v0, 0x2

    invoke-static {v14, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v10

    if-eqz v10, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :cond_9
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_a

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/ux0;

    invoke-static {v13, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v13

    invoke-static {v13, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_9

    goto :goto_5

    :cond_a
    :goto_4
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v0, v9, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_5

    :cond_b
    move-object v4, v13

    move-object v9, v14

    :goto_5
    iget-object v0, v9, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v0, Llyiahf/vczjk/up3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "thisDescriptor"

    invoke-static {v12, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "c"

    invoke-static {v9, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v9, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_15

    iget-object v3, v1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v3}, Ljava/lang/Class;->isAnnotation()Z

    move-result v8

    invoke-virtual {v3}, Ljava/lang/Class;->isInterface()Z

    if-nez v8, :cond_c

    :goto_6
    move-object v13, v4

    goto/16 :goto_f

    :cond_c
    iget-object v3, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s64;

    iget-object v3, v3, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v3

    const/4 v10, 0x1

    invoke-static {v12, v5, v10, v3}, Llyiahf/vczjk/e64;->o0000oOo(Llyiahf/vczjk/by0;Llyiahf/vczjk/ko;ZLlyiahf/vczjk/hz7;)Llyiahf/vczjk/e64;

    move-result-object v3

    if-eqz v8, :cond_13

    invoke-virtual {v1}, Llyiahf/vczjk/cm7;->OooO0Oo()Ljava/util/List;

    move-result-object v1

    move-object v5, v3

    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v8

    invoke-direct {v3, v8}, Ljava/util/ArrayList;-><init>(I)V

    sget-object v8, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v13, 0x6

    invoke-static {v8, v10, v4, v13}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v13

    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_e

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    move-object v15, v14

    check-cast v15, Llyiahf/vczjk/lm7;

    invoke-virtual {v15}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v15

    sget-object v4, Llyiahf/vczjk/dd4;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-static {v15, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_d

    invoke-virtual {v8, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_8

    :cond_d
    invoke-virtual {v10, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_8
    const/4 v4, 0x0

    goto :goto_7

    :cond_e
    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, v8, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/List;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    invoke-static {v4}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/lm7;

    iget-object v8, v11, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/uqa;

    if-eqz v4, :cond_10

    invoke-virtual {v4}, Llyiahf/vczjk/lm7;->OooO0o()Llyiahf/vczjk/pm7;

    move-result-object v8

    instance-of v14, v8, Llyiahf/vczjk/wl7;

    if-eqz v14, :cond_f

    new-instance v14, Llyiahf/vczjk/xn6;

    check-cast v8, Llyiahf/vczjk/wl7;

    move-object/from16 v16, v1

    const/4 v15, 0x1

    invoke-virtual {v10, v8, v13, v15}, Llyiahf/vczjk/uqa;->Oooo0oO(Llyiahf/vczjk/wl7;Llyiahf/vczjk/a74;Z)Llyiahf/vczjk/iaa;

    move-result-object v1

    iget-object v8, v8, Llyiahf/vczjk/wl7;->OooO0O0:Llyiahf/vczjk/pm7;

    invoke-virtual {v10, v8, v13}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v8

    invoke-direct {v14, v1, v8}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_9

    :cond_f
    move-object/from16 v16, v1

    new-instance v14, Llyiahf/vczjk/xn6;

    invoke-virtual {v10, v8, v13}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v1

    const/4 v8, 0x0

    invoke-direct {v14, v1, v8}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_9
    invoke-virtual {v14}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v14}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/uk4;

    move-object v14, v6

    move-object v6, v4

    move-object v4, v5

    const/4 v5, 0x0

    move-object/from16 v26, v7

    move-object v7, v1

    move-object/from16 v1, v26

    invoke-virtual/range {v2 .. v8}, Llyiahf/vczjk/rr4;->OooOo0O(Ljava/util/ArrayList;Llyiahf/vczjk/e64;ILlyiahf/vczjk/lm7;Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)V

    goto :goto_a

    :cond_10
    move-object/from16 v16, v1

    move-object v14, v6

    move-object v1, v7

    move-object v6, v4

    move-object v4, v5

    :goto_a
    if-eqz v6, :cond_11

    const/4 v15, 0x1

    goto :goto_b

    :cond_11
    const/4 v15, 0x0

    :goto_b
    invoke-interface/range {v16 .. v16}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v16

    const/4 v5, 0x0

    :goto_c
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_12

    add-int/lit8 v17, v5, 0x1

    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/lm7;

    invoke-virtual {v6}, Llyiahf/vczjk/lm7;->OooO0o()Llyiahf/vczjk/pm7;

    move-result-object v7

    invoke-virtual {v10, v7, v13}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v7

    add-int/2addr v5, v15

    const/4 v8, 0x0

    invoke-virtual/range {v2 .. v8}, Llyiahf/vczjk/rr4;->OooOo0O(Ljava/util/ArrayList;Llyiahf/vczjk/e64;ILlyiahf/vczjk/lm7;Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)V

    move/from16 v5, v17

    goto :goto_c

    :cond_12
    :goto_d
    const/4 v13, 0x0

    goto :goto_e

    :cond_13
    move-object v4, v3

    move-object v14, v6

    move-object v1, v7

    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    goto :goto_d

    :goto_e
    invoke-virtual {v4, v13}, Llyiahf/vczjk/e64;->o0000Oo(Z)V

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v2

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/j64;->OooO0O0:Llyiahf/vczjk/q72;

    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_14

    sget-object v2, Llyiahf/vczjk/j64;->OooO0OO:Llyiahf/vczjk/q72;

    invoke-static {v2, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_14
    invoke-virtual {v4, v3, v2}, Llyiahf/vczjk/ux0;->o0000o(Ljava/util/List;Llyiahf/vczjk/q72;)V

    const/4 v15, 0x1

    invoke-virtual {v4, v15}, Llyiahf/vczjk/e64;->o0000Oo0(Z)V

    invoke-interface {v12}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v1

    invoke-virtual {v4, v1}, Llyiahf/vczjk/tf3;->o0000OoO(Llyiahf/vczjk/dp8;)V

    iget-object v1, v11, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto/16 :goto_6

    :goto_f
    invoke-static {v13}, Llyiahf/vczjk/e21;->OoooO00(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    :cond_15
    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOo:Llyiahf/vczjk/tp3;

    invoke-virtual {v0, v9, v3}, Llyiahf/vczjk/tp3;->OooOOO0(Llyiahf/vczjk/ld9;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
