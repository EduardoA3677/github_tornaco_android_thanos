.class public final Llyiahf/vczjk/ta7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/qt5;

.field public OooO00o:Llyiahf/vczjk/v02;

.field public OooO0O0:Llyiahf/vczjk/yk5;

.field public OooO0OO:Llyiahf/vczjk/q72;

.field public OooO0Oo:Llyiahf/vczjk/sa7;

.field public OooO0o:Llyiahf/vczjk/g5a;

.field public OooO0o0:I

.field public OooO0oO:Z

.field public final OooO0oo:Llyiahf/vczjk/mp4;

.field public final OooOO0:Llyiahf/vczjk/uk4;

.field public final synthetic OooOO0O:Llyiahf/vczjk/ua7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ua7;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ta7;->OooOO0O:Llyiahf/vczjk/ua7;

    invoke-virtual {p1}, Llyiahf/vczjk/y02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO00o:Llyiahf/vczjk/v02;

    invoke-virtual {p1}, Llyiahf/vczjk/ua7;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO0O0:Llyiahf/vczjk/yk5;

    invoke-virtual {p1}, Llyiahf/vczjk/ua7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO0OO:Llyiahf/vczjk/q72;

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO0Oo:Llyiahf/vczjk/sa7;

    invoke-virtual {p1}, Llyiahf/vczjk/ua7;->getKind()I

    move-result v0

    iput v0, p0, Llyiahf/vczjk/ta7;->OooO0o0:I

    sget-object v0, Llyiahf/vczjk/g5a;->OooO00o:Llyiahf/vczjk/f5a;

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO0o:Llyiahf/vczjk/g5a;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ta7;->OooO0oO:Z

    iget-object v0, p1, Llyiahf/vczjk/ua7;->Oooo0:Llyiahf/vczjk/mp4;

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO0oo:Llyiahf/vczjk/mp4;

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ta7;->OooO:Llyiahf/vczjk/qt5;

    invoke-virtual {p1}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ta7;->OooOO0:Llyiahf/vczjk/uk4;

    return-void
.end method

.method public static synthetic OooO00o(I)V
    .locals 24

    move/from16 v0, p0

    const/16 v1, 0x11

    const/16 v2, 0x10

    const/16 v3, 0xe

    const/16 v4, 0xd

    const/16 v5, 0x13

    const/16 v6, 0xb

    const/16 v7, 0x9

    const/4 v8, 0x7

    const/4 v9, 0x5

    const/4 v10, 0x3

    const/4 v11, 0x2

    const/4 v12, 0x1

    if-eq v0, v12, :cond_0

    if-eq v0, v11, :cond_0

    if-eq v0, v10, :cond_0

    if-eq v0, v9, :cond_0

    if-eq v0, v8, :cond_0

    if-eq v0, v7, :cond_0

    if-eq v0, v6, :cond_0

    if-eq v0, v5, :cond_0

    if-eq v0, v4, :cond_0

    if-eq v0, v3, :cond_0

    if-eq v0, v2, :cond_0

    if-eq v0, v1, :cond_0

    const-string v13, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    goto :goto_0

    :cond_0
    const-string v13, "@NotNull method %s.%s must not return null"

    :goto_0
    if-eq v0, v12, :cond_1

    if-eq v0, v11, :cond_1

    if-eq v0, v10, :cond_1

    if-eq v0, v9, :cond_1

    if-eq v0, v8, :cond_1

    if-eq v0, v7, :cond_1

    if-eq v0, v6, :cond_1

    if-eq v0, v5, :cond_1

    if-eq v0, v4, :cond_1

    if-eq v0, v3, :cond_1

    if-eq v0, v2, :cond_1

    if-eq v0, v1, :cond_1

    move v14, v10

    goto :goto_1

    :cond_1
    move v14, v11

    :goto_1
    new-array v14, v14, [Ljava/lang/Object;

    const-string v15, "kotlin/reflect/jvm/internal/impl/descriptors/impl/PropertyDescriptorImpl$CopyConfiguration"

    const/16 v16, 0x0

    packed-switch v0, :pswitch_data_0

    const-string v17, "owner"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_0
    const-string v17, "name"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_1
    const-string v17, "substitution"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_2
    const-string v17, "typeParameters"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_3
    const-string v17, "kind"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_4
    const-string v17, "visibility"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_5
    const-string v17, "modality"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_6
    const-string v17, "type"

    aput-object v17, v14, v16

    goto :goto_2

    :pswitch_7
    aput-object v15, v14, v16

    :goto_2
    const-string v16, "setOwner"

    const-string v17, "setReturnType"

    const-string v18, "setModality"

    const-string v19, "setVisibility"

    const-string v20, "setKind"

    const-string v21, "setTypeParameters"

    const-string v22, "setSubstitution"

    const-string v23, "setName"

    if-eq v0, v12, :cond_d

    if-eq v0, v11, :cond_c

    if-eq v0, v10, :cond_b

    if-eq v0, v9, :cond_a

    if-eq v0, v8, :cond_9

    if-eq v0, v7, :cond_8

    if-eq v0, v6, :cond_7

    if-eq v0, v5, :cond_6

    if-eq v0, v4, :cond_5

    if-eq v0, v3, :cond_4

    if-eq v0, v2, :cond_3

    if-eq v0, v1, :cond_2

    aput-object v15, v14, v12

    goto :goto_3

    :cond_2
    const-string v15, "setCopyOverrides"

    aput-object v15, v14, v12

    goto :goto_3

    :cond_3
    aput-object v22, v14, v12

    goto :goto_3

    :cond_4
    const-string v15, "setDispatchReceiverParameter"

    aput-object v15, v14, v12

    goto :goto_3

    :cond_5
    aput-object v21, v14, v12

    goto :goto_3

    :cond_6
    aput-object v23, v14, v12

    goto :goto_3

    :cond_7
    aput-object v20, v14, v12

    goto :goto_3

    :cond_8
    aput-object v19, v14, v12

    goto :goto_3

    :cond_9
    aput-object v18, v14, v12

    goto :goto_3

    :cond_a
    aput-object v17, v14, v12

    goto :goto_3

    :cond_b
    const-string v15, "setPreserveSourceElement"

    aput-object v15, v14, v12

    goto :goto_3

    :cond_c
    const-string v15, "setOriginal"

    aput-object v15, v14, v12

    goto :goto_3

    :cond_d
    aput-object v16, v14, v12

    :goto_3
    packed-switch v0, :pswitch_data_1

    aput-object v16, v14, v11

    goto :goto_4

    :pswitch_8
    aput-object v23, v14, v11

    goto :goto_4

    :pswitch_9
    aput-object v22, v14, v11

    goto :goto_4

    :pswitch_a
    aput-object v21, v14, v11

    goto :goto_4

    :pswitch_b
    aput-object v20, v14, v11

    goto :goto_4

    :pswitch_c
    aput-object v19, v14, v11

    goto :goto_4

    :pswitch_d
    aput-object v18, v14, v11

    goto :goto_4

    :pswitch_e
    aput-object v17, v14, v11

    :goto_4
    :pswitch_f
    invoke-static {v13, v14}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v13

    if-eq v0, v12, :cond_e

    if-eq v0, v11, :cond_e

    if-eq v0, v10, :cond_e

    if-eq v0, v9, :cond_e

    if-eq v0, v8, :cond_e

    if-eq v0, v7, :cond_e

    if-eq v0, v6, :cond_e

    if-eq v0, v5, :cond_e

    if-eq v0, v4, :cond_e

    if-eq v0, v3, :cond_e

    if-eq v0, v2, :cond_e

    if-eq v0, v1, :cond_e

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v13}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    goto :goto_5

    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v13}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :goto_5
    throw v0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_6
        :pswitch_7
        :pswitch_5
        :pswitch_7
        :pswitch_4
        :pswitch_7
        :pswitch_3
        :pswitch_7
        :pswitch_2
        :pswitch_7
        :pswitch_7
        :pswitch_1
        :pswitch_7
        :pswitch_7
        :pswitch_0
        :pswitch_7
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_f
        :pswitch_f
        :pswitch_f
        :pswitch_e
        :pswitch_f
        :pswitch_d
        :pswitch_f
        :pswitch_c
        :pswitch_f
        :pswitch_b
        :pswitch_f
        :pswitch_a
        :pswitch_f
        :pswitch_f
        :pswitch_9
        :pswitch_f
        :pswitch_f
        :pswitch_8
        :pswitch_f
    .end packed-switch
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/ua7;
    .locals 18

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/ta7;->OooOO0O:Llyiahf/vczjk/ua7;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v0, Llyiahf/vczjk/ta7;->OooO00o:Llyiahf/vczjk/v02;

    iget-object v3, v0, Llyiahf/vczjk/ta7;->OooO0O0:Llyiahf/vczjk/yk5;

    iget-object v4, v0, Llyiahf/vczjk/ta7;->OooO0OO:Llyiahf/vczjk/q72;

    iget-object v5, v0, Llyiahf/vczjk/ta7;->OooO0Oo:Llyiahf/vczjk/sa7;

    iget v6, v0, Llyiahf/vczjk/ta7;->OooO0o0:I

    sget-object v17, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    iget-object v7, v0, Llyiahf/vczjk/ta7;->OooO:Llyiahf/vczjk/qt5;

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/ua7;->o000OO(Llyiahf/vczjk/v02;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/sa7;ILlyiahf/vczjk/qt5;)Llyiahf/vczjk/ua7;

    move-result-object v8

    invoke-virtual {v1}, Llyiahf/vczjk/ua7;->OooOOO()Ljava/util/List;

    move-result-object v2

    new-instance v10, Ljava/util/ArrayList;

    move-object v3, v2

    check-cast v3, Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v3

    invoke-direct {v10, v3}, Ljava/util/ArrayList;-><init>(I)V

    iget-object v3, v0, Llyiahf/vczjk/ta7;->OooO0o:Llyiahf/vczjk/g5a;

    invoke-static {v2, v3, v8, v10}, Llyiahf/vczjk/os9;->o000oOoO(Ljava/util/List;Llyiahf/vczjk/g5a;Llyiahf/vczjk/v02;Ljava/util/ArrayList;)Llyiahf/vczjk/i5a;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    iget-object v4, v0, Llyiahf/vczjk/ta7;->OooOO0:Llyiahf/vczjk/uk4;

    invoke-virtual {v2, v4, v3}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v9

    const/4 v3, 0x0

    if-nez v9, :cond_0

    goto :goto_0

    :cond_0
    sget-object v5, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    invoke-virtual {v2, v4, v5}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {v8, v4}, Llyiahf/vczjk/ua7;->o0000OOO(Llyiahf/vczjk/uk4;)V

    :cond_1
    iget-object v4, v0, Llyiahf/vczjk/ta7;->OooO0oo:Llyiahf/vczjk/mp4;

    if-eqz v4, :cond_3

    invoke-virtual {v4, v2}, Llyiahf/vczjk/mp4;->o0000O0O(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/mp4;

    move-result-object v4

    if-nez v4, :cond_2

    :goto_0
    return-object v3

    :cond_2
    move-object v11, v4

    goto :goto_1

    :cond_3
    move-object v11, v3

    :goto_1
    iget-object v4, v1, Llyiahf/vczjk/ua7;->Oooo0O0:Llyiahf/vczjk/mp4;

    if-eqz v4, :cond_5

    invoke-virtual {v4}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v6

    invoke-virtual {v2, v6, v5}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v5

    if-nez v5, :cond_4

    move-object v6, v3

    goto :goto_2

    :cond_4
    new-instance v6, Llyiahf/vczjk/mp4;

    new-instance v7, Llyiahf/vczjk/fu2;

    invoke-virtual {v4}, Llyiahf/vczjk/mp4;->o0000O0()Llyiahf/vczjk/vi7;

    invoke-direct {v7, v8, v5}, Llyiahf/vczjk/fu2;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;)V

    invoke-virtual {v4}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v4

    invoke-direct {v6, v8, v7, v4}, Llyiahf/vczjk/mp4;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/l21;Llyiahf/vczjk/ko;)V

    :goto_2
    move-object v12, v6

    goto :goto_3

    :cond_5
    move-object v12, v3

    :goto_3
    new-instance v13, Ljava/util/ArrayList;

    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    iget-object v4, v1, Llyiahf/vczjk/ua7;->Oooo00o:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_6
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/mp4;

    invoke-virtual {v5}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/cda;->OooOOO:Llyiahf/vczjk/cda;

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v6

    if-nez v6, :cond_7

    move-object v7, v3

    goto :goto_5

    :cond_7
    new-instance v7, Llyiahf/vczjk/mp4;

    new-instance v14, Llyiahf/vczjk/ln1;

    invoke-virtual {v5}, Llyiahf/vczjk/mp4;->o0000O0()Llyiahf/vczjk/vi7;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/ln1;

    invoke-virtual {v15}, Llyiahf/vczjk/ln1;->o0000oo()Llyiahf/vczjk/qt5;

    move-result-object v15

    invoke-virtual {v5}, Llyiahf/vczjk/mp4;->o0000O0()Llyiahf/vczjk/vi7;

    invoke-direct {v14, v8, v6, v15}, Llyiahf/vczjk/ln1;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/uk4;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v5

    invoke-direct {v7, v8, v14, v5}, Llyiahf/vczjk/mp4;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/l21;Llyiahf/vczjk/ko;)V

    :goto_5
    if-eqz v7, :cond_6

    invoke-virtual {v13, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_8
    invoke-virtual/range {v8 .. v13}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    iget-object v4, v1, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    const/4 v5, 0x2

    if-nez v4, :cond_9

    move-object v4, v3

    goto :goto_7

    :cond_9
    new-instance v7, Llyiahf/vczjk/va7;

    invoke-virtual {v4}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v9

    iget-object v10, v0, Llyiahf/vczjk/ta7;->OooO0O0:Llyiahf/vczjk/yk5;

    iget-object v4, v1, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    invoke-virtual {v4}, Llyiahf/vczjk/la7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v4

    iget v6, v0, Llyiahf/vczjk/ta7;->OooO0o0:I

    if-ne v6, v5, :cond_a

    iget-object v6, v4, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    invoke-virtual {v6}, Llyiahf/vczjk/oO0Oo0oo;->OooOO0O()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/r72;->OooO0o(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/r72;->OooO0o0(Llyiahf/vczjk/q72;)Z

    move-result v6

    if-eqz v6, :cond_a

    sget-object v4, Llyiahf/vczjk/r72;->OooO0oo:Llyiahf/vczjk/q72;

    :cond_a
    move-object v11, v4

    iget-object v4, v1, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    iget-boolean v12, v4, Llyiahf/vczjk/la7;->OooOo00:Z

    iget v15, v0, Llyiahf/vczjk/ta7;->OooO0o0:I

    iget-object v6, v0, Llyiahf/vczjk/ta7;->OooO0Oo:Llyiahf/vczjk/sa7;

    if-nez v6, :cond_b

    move-object/from16 v16, v3

    goto :goto_6

    :cond_b
    invoke-interface {v6}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object v6

    move-object/from16 v16, v6

    :goto_6
    iget-boolean v13, v4, Llyiahf/vczjk/la7;->OooOo0:Z

    iget-boolean v14, v4, Llyiahf/vczjk/la7;->OooOo:Z

    invoke-direct/range {v7 .. v17}, Llyiahf/vczjk/va7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/va7;Llyiahf/vczjk/sx8;)V

    move-object v4, v7

    :goto_7
    if-eqz v4, :cond_d

    iget-object v6, v1, Llyiahf/vczjk/ua7;->Oooo0o0:Llyiahf/vczjk/va7;

    iget-object v7, v6, Llyiahf/vczjk/va7;->OooOoo0:Llyiahf/vczjk/uk4;

    invoke-static {v2, v6}, Llyiahf/vczjk/ua7;->o0000O(Llyiahf/vczjk/i5a;Llyiahf/vczjk/ka7;)Llyiahf/vczjk/rf3;

    move-result-object v6

    iput-object v6, v4, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    if-eqz v7, :cond_c

    sget-object v6, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    invoke-virtual {v2, v7, v6}, Llyiahf/vczjk/i5a;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object v6

    goto :goto_8

    :cond_c
    move-object v6, v3

    :goto_8
    invoke-virtual {v4, v6}, Llyiahf/vczjk/va7;->o0000O(Llyiahf/vczjk/uk4;)V

    :cond_d
    iget-object v6, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    if-nez v6, :cond_e

    move-object v11, v3

    goto :goto_a

    :cond_e
    new-instance v7, Llyiahf/vczjk/hb7;

    invoke-virtual {v6}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v9

    iget-object v10, v0, Llyiahf/vczjk/ta7;->OooO0O0:Llyiahf/vczjk/yk5;

    iget-object v6, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    invoke-virtual {v6}, Llyiahf/vczjk/la7;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v6

    iget v11, v0, Llyiahf/vczjk/ta7;->OooO0o0:I

    if-ne v11, v5, :cond_f

    iget-object v5, v6, Llyiahf/vczjk/q72;->OooO00o:Llyiahf/vczjk/oO0Oo0oo;

    invoke-virtual {v5}, Llyiahf/vczjk/oO0Oo0oo;->OooOO0O()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/r72;->OooO0o(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/r72;->OooO0o0(Llyiahf/vczjk/q72;)Z

    move-result v5

    if-eqz v5, :cond_f

    sget-object v6, Llyiahf/vczjk/r72;->OooO0oo:Llyiahf/vczjk/q72;

    :cond_f
    move-object v11, v6

    iget-object v5, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    iget-boolean v12, v5, Llyiahf/vczjk/la7;->OooOo00:Z

    iget v15, v0, Llyiahf/vczjk/ta7;->OooO0o0:I

    iget-object v6, v0, Llyiahf/vczjk/ta7;->OooO0Oo:Llyiahf/vczjk/sa7;

    if-nez v6, :cond_10

    move-object/from16 v16, v3

    goto :goto_9

    :cond_10
    invoke-interface {v6}, Llyiahf/vczjk/sa7;->OooO0OO()Llyiahf/vczjk/hb7;

    move-result-object v6

    move-object/from16 v16, v6

    :goto_9
    iget-boolean v13, v5, Llyiahf/vczjk/la7;->OooOo0:Z

    iget-boolean v14, v5, Llyiahf/vczjk/la7;->OooOo:Z

    invoke-direct/range {v7 .. v17}, Llyiahf/vczjk/hb7;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZZZILlyiahf/vczjk/hb7;Llyiahf/vczjk/sx8;)V

    move-object v11, v7

    :goto_a
    if-eqz v11, :cond_14

    iget-object v5, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    invoke-virtual {v5}, Llyiahf/vczjk/hb7;->OoooOOO()Ljava/util/List;

    move-result-object v12

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    move-object v13, v2

    invoke-static/range {v11 .. v16}, Llyiahf/vczjk/tf3;->o0000OO0(Llyiahf/vczjk/rf3;Ljava/util/List;Llyiahf/vczjk/i5a;ZZ[Z)Ljava/util/ArrayList;

    move-result-object v2

    const/4 v5, 0x0

    if-nez v2, :cond_11

    iget-object v2, v0, Llyiahf/vczjk/ta7;->OooO00o:Llyiahf/vczjk/v02;

    invoke-static {v2}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/hk4;->OooOOOO()Llyiahf/vczjk/dp8;

    move-result-object v2

    iget-object v6, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    invoke-virtual {v6}, Llyiahf/vczjk/hb7;->OoooOOO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tca;

    check-cast v6, Llyiahf/vczjk/l21;

    invoke-virtual {v6}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v6

    invoke-static {v11, v2, v6}, Llyiahf/vczjk/hb7;->o000OO(Llyiahf/vczjk/hb7;Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/tca;

    move-result-object v2

    invoke-static {v2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    :cond_11
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v6

    const/4 v7, 0x1

    if-ne v6, v7, :cond_13

    iget-object v6, v1, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    invoke-static {v13, v6}, Llyiahf/vczjk/ua7;->o0000O(Llyiahf/vczjk/i5a;Llyiahf/vczjk/ka7;)Llyiahf/vczjk/rf3;

    move-result-object v6

    iput-object v6, v11, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tca;

    if-eqz v2, :cond_12

    iput-object v2, v11, Llyiahf/vczjk/hb7;->OooOoo0:Llyiahf/vczjk/tca;

    goto :goto_b

    :cond_12
    const/4 v1, 0x6

    invoke-static {v1}, Llyiahf/vczjk/hb7;->o00000O0(I)V

    throw v3

    :cond_13
    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-direct {v1}, Ljava/lang/IllegalStateException;-><init>()V

    throw v1

    :cond_14
    move-object v13, v2

    :goto_b
    iget-object v2, v1, Llyiahf/vczjk/ua7;->Oooo0oO:Llyiahf/vczjk/fx2;

    if-nez v2, :cond_15

    move-object v5, v3

    goto :goto_c

    :cond_15
    new-instance v5, Llyiahf/vczjk/fx2;

    invoke-virtual {v2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    invoke-direct {v5, v2, v8}, Llyiahf/vczjk/fx2;-><init>(Llyiahf/vczjk/ko;Llyiahf/vczjk/ua7;)V

    :goto_c
    iget-object v2, v1, Llyiahf/vczjk/ua7;->Oooo0oo:Llyiahf/vczjk/fx2;

    if-nez v2, :cond_16

    goto :goto_d

    :cond_16
    new-instance v3, Llyiahf/vczjk/fx2;

    invoke-virtual {v2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    invoke-direct {v3, v2, v8}, Llyiahf/vczjk/fx2;-><init>(Llyiahf/vczjk/ko;Llyiahf/vczjk/ua7;)V

    :goto_d
    invoke-virtual {v8, v4, v11, v5, v3}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    iget-boolean v2, v0, Llyiahf/vczjk/ta7;->OooO0oO:Z

    if-eqz v2, :cond_18

    new-instance v2, Llyiahf/vczjk/dt8;

    invoke-direct {v2}, Llyiahf/vczjk/dt8;-><init>()V

    invoke-virtual {v1}, Llyiahf/vczjk/ua7;->OooOOO0()Ljava/util/Collection;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_e
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_17

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/sa7;

    invoke-interface {v4, v13}, Llyiahf/vczjk/sa7;->OooO0o0(Llyiahf/vczjk/i5a;)Llyiahf/vczjk/sa7;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/dt8;->add(Ljava/lang/Object;)Z

    goto :goto_e

    :cond_17
    iput-object v2, v8, Llyiahf/vczjk/ua7;->OooOoO:Ljava/util/Collection;

    :cond_18
    invoke-virtual {v1}, Llyiahf/vczjk/ua7;->OooOoO0()Z

    move-result v2

    if-eqz v2, :cond_19

    iget-object v2, v1, Llyiahf/vczjk/ua7;->OooOo0o:Llyiahf/vczjk/le3;

    if-eqz v2, :cond_19

    iget-object v1, v1, Llyiahf/vczjk/ua7;->OooOo0O:Llyiahf/vczjk/n45;

    invoke-virtual {v8, v1, v2}, Llyiahf/vczjk/ua7;->o0000OO(Llyiahf/vczjk/n45;Llyiahf/vczjk/le3;)V

    :cond_19
    return-object v8
.end method
