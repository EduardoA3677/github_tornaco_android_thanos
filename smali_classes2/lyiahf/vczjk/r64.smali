.class public Llyiahf/vczjk/r64;
.super Llyiahf/vczjk/ua7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d64;


# instance fields
.field public final Oooo:Z

.field public final OoooO00:Llyiahf/vczjk/xn6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;Llyiahf/vczjk/sa7;IZLlyiahf/vczjk/xn6;)V
    .locals 15

    const/4 v0, 0x0

    if-eqz p1, :cond_6

    if-eqz p2, :cond_5

    if-eqz p3, :cond_4

    if-eqz p4, :cond_3

    if-eqz p6, :cond_2

    if-eqz p7, :cond_1

    if-eqz p9, :cond_0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v10, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object v0, p0

    move-object/from16 v1, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v9, p7

    move-object/from16 v2, p8

    move/from16 v8, p9

    invoke-direct/range {v0 .. v14}, Llyiahf/vczjk/ua7;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;ILlyiahf/vczjk/sx8;ZZZZZ)V

    move/from16 v0, p10

    iput-boolean v0, p0, Llyiahf/vczjk/r64;->Oooo:Z

    move-object/from16 v0, p11

    iput-object v0, p0, Llyiahf/vczjk/r64;->OoooO00:Llyiahf/vczjk/xn6;

    return-void

    :cond_0
    const/4 v2, 0x6

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_1
    const/4 v2, 0x5

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_2
    const/4 v2, 0x4

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_3
    const/4 v2, 0x3

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_4
    const/4 v2, 0x2

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_5
    const/4 v2, 0x1

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_6
    const/4 v2, 0x0

    invoke-static {v2}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0
.end method

.method public static synthetic o00000O0(I)V
    .locals 7

    const/16 v0, 0x15

    if-eq p0, v0, :cond_0

    const-string v1, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :cond_0
    const-string v1, "@NotNull method %s.%s must not return null"

    :goto_0
    const/4 v2, 0x2

    if-eq p0, v0, :cond_1

    const/4 v3, 0x3

    goto :goto_1

    :cond_1
    move v3, v2

    :goto_1
    new-array v3, v3, [Ljava/lang/Object;

    const-string v4, "kotlin/reflect/jvm/internal/impl/load/java/descriptors/JavaPropertyDescriptor"

    const/4 v5, 0x0

    packed-switch p0, :pswitch_data_0

    :pswitch_0
    const-string v6, "containingDeclaration"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_1
    const-string v6, "inType"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_2
    aput-object v4, v3, v5

    goto :goto_2

    :pswitch_3
    const-string v6, "enhancedReturnType"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_4
    const-string v6, "enhancedValueParameterTypes"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_5
    const-string v6, "newName"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_6
    const-string v6, "newVisibility"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_7
    const-string v6, "newModality"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_8
    const-string v6, "newOwner"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_9
    const-string v6, "kind"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_a
    const-string v6, "source"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_b
    const-string v6, "name"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_c
    const-string v6, "visibility"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_d
    const-string v6, "modality"

    aput-object v6, v3, v5

    goto :goto_2

    :pswitch_e
    const-string v6, "annotations"

    aput-object v6, v3, v5

    :goto_2
    const-string v5, "enhance"

    const/4 v6, 0x1

    if-eq p0, v0, :cond_2

    aput-object v4, v3, v6

    goto :goto_3

    :cond_2
    aput-object v5, v3, v6

    :goto_3
    packed-switch p0, :pswitch_data_1

    const-string v4, "<init>"

    aput-object v4, v3, v2

    goto :goto_4

    :pswitch_f
    const-string v4, "setInType"

    aput-object v4, v3, v2

    goto :goto_4

    :pswitch_10
    aput-object v5, v3, v2

    goto :goto_4

    :pswitch_11
    const-string v4, "createSubstitutedCopy"

    aput-object v4, v3, v2

    goto :goto_4

    :pswitch_12
    const-string v4, "create"

    aput-object v4, v3, v2

    :goto_4
    :pswitch_13
    invoke-static {v1, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    if-eq p0, v0, :cond_3

    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_0
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_9
        :pswitch_5
        :pswitch_a
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x7
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_12
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_11
        :pswitch_10
        :pswitch_10
        :pswitch_13
        :pswitch_f
    .end packed-switch
.end method

.method public static o0000Oo0(Llyiahf/vczjk/v02;Llyiahf/vczjk/lr4;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/hz7;Z)Llyiahf/vczjk/r64;
    .locals 12

    sget-object v3, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    const/4 v0, 0x0

    if-eqz p0, :cond_1

    if-eqz p4, :cond_0

    new-instance v0, Llyiahf/vczjk/r64;

    const/4 v11, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x1

    move-object v1, p0

    move-object v2, p1

    move-object v4, p2

    move v5, p3

    move-object/from16 v6, p4

    move-object/from16 v7, p5

    move/from16 v10, p6

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/r64;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;Llyiahf/vczjk/sa7;IZLlyiahf/vczjk/xn6;)V

    return-object v0

    :cond_0
    const/16 p0, 0xb

    invoke-static {p0}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_1
    const/4 p0, 0x7

    invoke-static {p0}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0
.end method


# virtual methods
.method public final OooOoO0()Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    iget-boolean v1, p0, Llyiahf/vczjk/r64;->Oooo:Z

    if-eqz v1, :cond_4

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/hk4;->Oooo00O(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/aaa;->OooO00o(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_1

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_2

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/hk4;->Oooo00o(Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_4

    :cond_2
    sget-object v1, Llyiahf/vczjk/z3a;->OooO00o:Llyiahf/vczjk/po;

    sget-object v1, Llyiahf/vczjk/dd4;->OooOOOo:Llyiahf/vczjk/hc3;

    const-string v2, "ENHANCED_NULLABILITY_ANNOTATION"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/m6a;->OoooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/hc3;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/hk4;->Oooo00o(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_4

    :cond_3
    const/4 v0, 0x1

    return v0

    :cond_4
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo00O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0o0(Llyiahf/vczjk/k82;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r64;->OoooO00:Llyiahf/vczjk/xn6;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/k82;

    invoke-virtual {v1, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final o0000OOO(Llyiahf/vczjk/uk4;)V
    .locals 0

    return-void
.end method

.method public final o000OO(Llyiahf/vczjk/v02;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/sa7;ILlyiahf/vczjk/qt5;)Llyiahf/vczjk/ua7;
    .locals 12

    sget-object v7, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    const/4 v0, 0x0

    if-eqz p1, :cond_4

    if-eqz p2, :cond_3

    if-eqz p3, :cond_2

    if-eqz p5, :cond_1

    if-eqz p6, :cond_0

    new-instance v0, Llyiahf/vczjk/r64;

    invoke-virtual {p0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    iget-object v11, p0, Llyiahf/vczjk/r64;->OoooO00:Llyiahf/vczjk/xn6;

    iget-boolean v5, p0, Llyiahf/vczjk/ua7;->OooOo0:Z

    iget-boolean v10, p0, Llyiahf/vczjk/r64;->Oooo:Z

    move-object v1, p1

    move-object v3, p2

    move-object v4, p3

    move-object/from16 v8, p4

    move/from16 v9, p5

    move-object/from16 v6, p6

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/r64;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;Llyiahf/vczjk/sa7;IZLlyiahf/vczjk/xn6;)V

    return-object v0

    :cond_0
    const/16 p1, 0x11

    invoke-static {p1}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_1
    const/16 p1, 0x10

    invoke-static {p1}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_2
    const/16 p1, 0xf

    invoke-static {p1}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_3
    const/16 p1, 0xe

    invoke-static {p1}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0

    :cond_4
    const/16 p1, 0xd

    invoke-static {p1}, Llyiahf/vczjk/r64;->o00000O0(I)V

    throw v0
.end method

.method public final oo000o(Llyiahf/vczjk/uk4;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Llyiahf/vczjk/xn6;)Llyiahf/vczjk/d64;
    .locals 24

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooO00o()Llyiahf/vczjk/sa7;

    move-result-object v2

    const/4 v3, 0x0

    if-ne v2, v0, :cond_0

    move-object v12, v3

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooO00o()Llyiahf/vczjk/sa7;

    move-result-object v2

    move-object v12, v2

    :goto_0
    new-instance v14, Llyiahf/vczjk/r64;

    invoke-virtual {v0}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v5

    invoke-virtual {v0}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v6

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v7

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v8

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v10

    invoke-virtual {v0}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v11

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v13

    move-object v4, v14

    iget-boolean v14, v0, Llyiahf/vczjk/r64;->Oooo:Z

    iget-boolean v9, v0, Llyiahf/vczjk/ua7;->OooOo0:Z

    move-object/from16 v15, p4

    invoke-direct/range {v4 .. v15}, Llyiahf/vczjk/r64;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;Llyiahf/vczjk/sa7;IZLlyiahf/vczjk/xn6;)V

    iget-object v2, v0, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    if-eqz v2, :cond_2

    new-instance v13, Llyiahf/vczjk/va7;

    invoke-virtual {v2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v15

    invoke-virtual {v2}, Llyiahf/vczjk/la7;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v16

    invoke-virtual {v2}, Llyiahf/vczjk/la7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v17

    iget-boolean v5, v2, Llyiahf/vczjk/la7;->OooOo00:Z

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v21

    if-nez v12, :cond_1

    move-object/from16 v22, v3

    goto :goto_1

    :cond_1
    invoke-interface {v12}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object v6

    move-object/from16 v22, v6

    :goto_1
    invoke-virtual {v2}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v23

    iget-boolean v6, v2, Llyiahf/vczjk/la7;->OooOo0:Z

    iget-boolean v7, v2, Llyiahf/vczjk/la7;->OooOo:Z

    move-object v14, v4

    move/from16 v18, v5

    move/from16 v19, v6

    move/from16 v20, v7

    invoke-direct/range {v13 .. v23}, Llyiahf/vczjk/va7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/va7;Llyiahf/vczjk/sx8;)V

    iget-object v2, v2, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    iput-object v2, v13, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    move-object/from16 v5, p3

    iput-object v5, v13, Llyiahf/vczjk/va7;->OooOoo0:Llyiahf/vczjk/uk4;

    move-object v2, v13

    goto :goto_2

    :cond_2
    move-object/from16 v5, p3

    move-object v2, v3

    :goto_2
    iget-object v6, v0, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    if-eqz v6, :cond_5

    new-instance v13, Llyiahf/vczjk/hb7;

    invoke-virtual {v6}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v15

    invoke-virtual {v6}, Llyiahf/vczjk/la7;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v16

    invoke-virtual {v6}, Llyiahf/vczjk/la7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v17

    iget-boolean v7, v6, Llyiahf/vczjk/la7;->OooOo00:Z

    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v21

    if-nez v12, :cond_3

    move-object/from16 v22, v3

    goto :goto_3

    :cond_3
    invoke-interface {v12}, Llyiahf/vczjk/sa7;->OooO0OO()Llyiahf/vczjk/hb7;

    move-result-object v8

    move-object/from16 v22, v8

    :goto_3
    invoke-virtual {v6}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v23

    iget-boolean v8, v6, Llyiahf/vczjk/la7;->OooOo0:Z

    iget-boolean v9, v6, Llyiahf/vczjk/la7;->OooOo:Z

    move-object v14, v4

    move/from16 v18, v7

    move/from16 v19, v8

    move/from16 v20, v9

    invoke-direct/range {v13 .. v23}, Llyiahf/vczjk/hb7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/hb7;Llyiahf/vczjk/sx8;)V

    iget-object v7, v13, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    iput-object v7, v13, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    invoke-virtual {v6}, Llyiahf/vczjk/hb7;->OoooOOO()Ljava/util/List;

    move-result-object v6

    const/4 v7, 0x0

    invoke-interface {v6, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tca;

    if-eqz v6, :cond_4

    iput-object v6, v13, Llyiahf/vczjk/hb7;->OooOoo0:Llyiahf/vczjk/tca;

    goto :goto_4

    :cond_4
    const/4 v1, 0x6

    invoke-static {v1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v3

    :cond_5
    move-object v13, v3

    :goto_4
    iget-object v6, v0, Llyiahf/vczjk/ua7;->Oooo0oO:Llyiahf/vczjk/fx2;

    iget-object v7, v0, Llyiahf/vczjk/ua7;->Oooo0oo:Llyiahf/vczjk/fx2;

    invoke-virtual {v4, v2, v13, v6, v7}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    iget-object v2, v0, Llyiahf/vczjk/ua7;->OooOo0o:Llyiahf/vczjk/le3;

    if-eqz v2, :cond_6

    iget-object v6, v0, Llyiahf/vczjk/ua7;->OooOo0O:Llyiahf/vczjk/n45;

    invoke-virtual {v4, v6, v2}, Llyiahf/vczjk/ua7;->o0000OO(Llyiahf/vczjk/n45;Llyiahf/vczjk/le3;)V

    :cond_6
    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooOOO0()Ljava/util/Collection;

    move-result-object v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ua7;->o00oO0O(Ljava/util/Collection;)V

    if-nez v1, :cond_7

    :goto_5
    move-object v8, v3

    goto :goto_6

    :cond_7
    sget-object v2, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/dn8;->OoooO0O(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/mp4;

    move-result-object v3

    goto :goto_5

    :goto_6
    invoke-virtual {v0}, Llyiahf/vczjk/ua7;->OooOOO()Ljava/util/List;

    move-result-object v6

    iget-object v7, v0, Llyiahf/vczjk/ua7;->Oooo0:Llyiahf/vczjk/mp4;

    sget-object v9, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-virtual/range {v4 .. v9}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    return-object v4
.end method
