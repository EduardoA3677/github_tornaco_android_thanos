.class public abstract Llyiahf/vczjk/l4a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO:I

.field public static final OooO00o:[[F

.field public static final OooO0O0:[[F

.field public static final OooO0OO:[F

.field public static final OooO0Oo:[[F

.field public static final OooO0o:[Llyiahf/vczjk/bt4;

.field public static final OooO0o0:[Ljava/lang/String;

.field public static final OooO0oO:[Ljava/lang/StackTraceElement;

.field public static final OooO0oo:Llyiahf/vczjk/ms8;

.field public static final synthetic OooOO0:I

.field public static OooOO0O:Llyiahf/vczjk/ld9;

.field public static final synthetic OooOO0o:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 5

    const/4 v0, 0x0

    const/4 v1, 0x3

    new-array v2, v1, [F

    fill-array-data v2, :array_0

    new-array v3, v1, [F

    fill-array-data v3, :array_1

    new-array v4, v1, [F

    fill-array-data v4, :array_2

    filled-new-array {v2, v3, v4}, [[F

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/l4a;->OooO00o:[[F

    new-array v2, v1, [F

    fill-array-data v2, :array_3

    new-array v3, v1, [F

    fill-array-data v3, :array_4

    new-array v4, v1, [F

    fill-array-data v4, :array_5

    filled-new-array {v2, v3, v4}, [[F

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/l4a;->OooO0O0:[[F

    new-array v2, v1, [F

    fill-array-data v2, :array_6

    sput-object v2, Llyiahf/vczjk/l4a;->OooO0OO:[F

    new-array v2, v1, [F

    fill-array-data v2, :array_7

    new-array v3, v1, [F

    fill-array-data v3, :array_8

    new-array v1, v1, [F

    fill-array-data v1, :array_9

    filled-new-array {v2, v3, v1}, [[F

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/l4a;->OooO0Oo:[[F

    new-array v1, v0, [Ljava/lang/String;

    sput-object v1, Llyiahf/vczjk/l4a;->OooO0o0:[Ljava/lang/String;

    new-array v1, v0, [Llyiahf/vczjk/bt4;

    sput-object v1, Llyiahf/vczjk/l4a;->OooO0o:[Llyiahf/vczjk/bt4;

    new-array v0, v0, [Ljava/lang/StackTraceElement;

    sput-object v0, Llyiahf/vczjk/l4a;->OooO0oO:[Ljava/lang/StackTraceElement;

    new-instance v0, Llyiahf/vczjk/ms8;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/ms8;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/l4a;->OooO0oo:Llyiahf/vczjk/ms8;

    return-void

    nop

    :array_0
    .array-data 4
        0x3ecd759f
        0x3f2671bd
        -0x42ad373b    # -0.051461f
    .end array-data

    :array_1
    .array-data 4
        -0x417fdcdf
        0x3f9a2a3d
        0x3d3bd167
    .end array-data

    :array_2
    .array-data 4
        -0x44f7c02b    # -0.002079f
        0x3d4881e4
        0x3f740022
    .end array-data

    :array_3
    .array-data 4
        0x3fee583d
        -0x407e8f35
        0x3e18c46b
    .end array-data

    :array_4
    .array-data 4
        0x3ec669e1
        0x3f1f172e
        -0x43ecf866
    .end array-data

    :array_5
    .array-data 4
        -0x437e39f7
        -0x42f43b81
        0x3f86653c
    .end array-data

    :array_6
    .array-data 4
        0x42be1810
        0x42c80000    # 100.0f
        0x42d9c419
    .end array-data

    :array_7
    .array-data 4
        0x3ed31e17
        0x3eb71a0d
        0x3e38d7b9
    .end array-data

    :array_8
    .array-data 4
        0x3e59b3d0    # 0.2126f
        0x3f371759    # 0.7152f
        0x3d93dd98    # 0.0722f
    .end array-data

    :array_9
    .array-data 4
        0x3c9e47ef
        0x3df40c29
        0x3f7349cc
    .end array-data
.end method

.method public static OooO(Ljava/lang/Object;)Ljava/util/Set;
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/cg4;

    if-eqz v0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/sg4;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const-string v0, "kotlin.collections.MutableSet"

    invoke-static {p0, v0}, Llyiahf/vczjk/l4a;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0

    :cond_1
    :goto_0
    :try_start_0
    check-cast p0, Ljava/util/Set;
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    const-class v0, Llyiahf/vczjk/l4a;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->Oooooo(Ljava/lang/RuntimeException;Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 19

    move-wide/from16 v2, p1

    move-object/from16 v4, p3

    const/4 v1, 0x0

    const-string v5, "onColorChanged"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v9, p4

    check-cast v9, Llyiahf/vczjk/zf1;

    const v5, -0x40d57a80

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, v2, v3}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v5

    const/16 v12, 0x20

    if-eqz v5, :cond_0

    move v5, v12

    goto :goto_0

    :cond_0
    const/16 v5, 0x10

    :goto_0
    or-int v5, p5, v5

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1

    const/16 v6, 0x800

    goto :goto_1

    :cond_1
    const/16 v6, 0x400

    :goto_1
    or-int/2addr v5, v6

    and-int/lit16 v6, v5, 0x493

    const/16 v7, 0x492

    if-ne v6, v7, :cond_3

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_c

    :cond_3
    :goto_2
    new-array v6, v1, [Ljava/lang/Object;

    sget-object v7, Llyiahf/vczjk/gp3;->OooO0o0:Llyiahf/vczjk/era;

    const v8, 0x4c5de2

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v5, v5, 0x70

    if-ne v5, v12, :cond_4

    const/4 v5, 0x1

    goto :goto_3

    :cond_4
    move v5, v1

    :goto_3
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_5

    if-ne v8, v13, :cond_6

    :cond_5
    new-instance v8, Llyiahf/vczjk/az0;

    invoke-direct {v8, v2, v3}, Llyiahf/vczjk/az0;-><init>(J)V

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v6

    const-string v5, "null cannot be cast to non-null type androidx.compose.runtime.saveable.Saver<T of androidx.compose.runtime.saveable.RememberSaveableKt.mutableStateSaver, kotlin.Any>"

    invoke-static {v7, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/po7;

    invoke-direct {v5, v7}, Llyiahf/vczjk/po7;-><init>(Llyiahf/vczjk/era;)V

    new-instance v10, Llyiahf/vczjk/qo7;

    invoke-direct {v10, v7}, Llyiahf/vczjk/qo7;-><init>(Llyiahf/vczjk/era;)V

    sget-object v7, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance v7, Llyiahf/vczjk/era;

    invoke-direct {v7, v5, v10}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qs5;

    sget-object v6, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v7, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    invoke-static {v6, v7, v9, v1}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v6

    iget v7, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    move-object/from16 v10, p0

    invoke-static {v9, v10}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_7

    invoke-virtual {v9, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v6, v9, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v9, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v1, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_8

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9

    :cond_8
    invoke-static {v7, v9, v7, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v11, v9, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    int-to-float v1, v12

    const/16 v7, 0x8

    int-to-float v7, v7

    invoke-static {v4, v9}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v2, 0x3f4ccccd    # 0.8f

    float-to-double v3, v2

    const-wide/16 v16, 0x0

    cmpl-double v3, v3, v16

    if-lez v3, :cond_a

    const/4 v4, 0x1

    goto :goto_5

    :cond_a
    const/4 v4, 0x0

    :goto_5
    const-string v16, "invalid weight; must be greater than zero"

    if-nez v4, :cond_b

    invoke-static/range {v16 .. v16}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :cond_b
    new-instance v4, Landroidx/compose/foundation/layout/LayoutWeightElement;

    move/from16 p4, v3

    const/4 v3, 0x1

    invoke-direct {v4, v2, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v10, 0x0

    invoke-static {v3, v2, v9, v10}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    iget v3, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v9, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v18, v1

    iget-boolean v1, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v1, :cond_c

    invoke-virtual {v9, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_c
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v2, v9, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v9, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_d

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_e

    :cond_d
    invoke-static {v3, v9, v3, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v4, v9, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-lez p4, :cond_f

    goto :goto_7

    :cond_f
    invoke-static/range {v16 .. v16}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_7
    new-instance v0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const v1, 0x3f4ccccd    # 0.8f

    const/4 v3, 0x1

    invoke-direct {v0, v1, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gp3;

    const v2, -0x615d173a

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v9, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_10

    if-ne v4, v13, :cond_11

    :cond_10
    new-instance v4, Llyiahf/vczjk/e2;

    const/4 v3, 0x5

    invoke-direct {v4, v3, v5, v11}, Llyiahf/vczjk/e2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v10, 0x0

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v1, v4, v9, v10}, Llyiahf/vczjk/er8;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/gp3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    const v0, -0x42904efd

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v12, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v9, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    move/from16 v0, v18

    invoke-static {v12, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/gp3;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v9, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_13

    if-ne v6, v13, :cond_12

    goto :goto_8

    :cond_12
    const/4 v10, 0x0

    goto :goto_9

    :cond_13
    :goto_8
    new-instance v6, Llyiahf/vczjk/bz0;

    const/4 v10, 0x0

    invoke-direct {v6, v5, v11, v10}, Llyiahf/vczjk/bz0;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_9
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x6

    invoke-static {v1, v3, v6, v9, v4}, Llyiahf/vczjk/v34;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/gp3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v3, 0x1

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v12, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v9, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-static {v12, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gp3;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v9, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_15

    if-ne v3, v13, :cond_14

    goto :goto_a

    :cond_14
    const/4 v2, 0x1

    goto :goto_b

    :cond_15
    :goto_a
    new-instance v3, Llyiahf/vczjk/bz0;

    const/4 v2, 0x1

    invoke-direct {v3, v5, v11, v2}, Llyiahf/vczjk/bz0;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_b
    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v10, 0x0

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v1, v3, v9, v4}, Llyiahf/vczjk/dn8;->OooOo00(Llyiahf/vczjk/kl5;Llyiahf/vczjk/gp3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_c
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_16

    new-instance v0, Llyiahf/vczjk/cz0;

    move-object/from16 v1, p0

    move-wide/from16 v2, p1

    move-object/from16 v4, p3

    move/from16 v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/cz0;-><init>(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/oe3;I)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_16
    return-void
.end method

.method public static OooO0O0()Llyiahf/vczjk/v51;
    .locals 2

    new-instance v0, Llyiahf/vczjk/v51;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/k84;-><init>(Z)V

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->Oooo0O0(Llyiahf/vczjk/v74;)V

    return-object v0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Ljava/lang/Throwable;Llyiahf/vczjk/rf1;I)V
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modifier"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "imageOptions"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p4, Llyiahf/vczjk/zf1;

    const v0, 0x13ee64de

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p5

    invoke-virtual {p4, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x100

    goto :goto_2

    :cond_2
    const/16 v1, 0x80

    :goto_2
    or-int/2addr v0, v1

    invoke-virtual {p4, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    const/16 v1, 0x800

    goto :goto_3

    :cond_3
    const/16 v1, 0x400

    :goto_3
    or-int/2addr v0, v1

    and-int/lit16 v0, v0, 0x493

    const/16 v1, 0x492

    if-ne v0, v1, :cond_5

    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_6

    :cond_5
    :goto_4
    iget-object v0, p0, Llyiahf/vczjk/iv3;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_5

    :cond_6
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_8

    :goto_6
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p4

    if-eqz p4, :cond_7

    new-instance v0, Llyiahf/vczjk/d5;

    const/4 v6, 0x2

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p4, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void

    :cond_8
    invoke-static {v0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modifier"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "imageOptions"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p4, Llyiahf/vczjk/zf1;

    const v0, -0x5f903d24

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p5

    invoke-virtual {p4, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x100

    goto :goto_2

    :cond_2
    const/16 v1, 0x80

    :goto_2
    or-int/2addr v0, v1

    and-int/lit16 v0, v0, 0x493

    const/16 v1, 0x492

    if-ne v0, v1, :cond_4

    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_4
    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/iv3;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_4

    :cond_5
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_7

    :goto_5
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p4

    if-eqz p4, :cond_6

    new-instance v0, Llyiahf/vczjk/d5;

    const/4 v6, 0x3

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p4, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void

    :cond_7
    invoke-static {v0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/nt4;Ljava/lang/Object;ILjava/lang/Object;Llyiahf/vczjk/rf1;I)V
    .locals 6

    check-cast p4, Llyiahf/vczjk/zf1;

    const v0, 0x55d242fd

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p5, 0x6

    if-nez v0, :cond_1

    invoke-virtual {p4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p5

    goto :goto_1

    :cond_1
    move v0, p5

    :goto_1
    and-int/lit8 v1, p5, 0x30

    if-nez v1, :cond_3

    invoke-virtual {p4, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit16 v1, p5, 0x180

    if-nez v1, :cond_5

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x100

    goto :goto_3

    :cond_4
    const/16 v1, 0x80

    :goto_3
    or-int/2addr v0, v1

    :cond_5
    and-int/lit16 v1, p5, 0xc00

    if-nez v1, :cond_7

    invoke-virtual {p4, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_6

    const/16 v1, 0x800

    goto :goto_4

    :cond_6
    const/16 v1, 0x400

    :goto_4
    or-int/2addr v0, v1

    :cond_7
    and-int/lit16 v1, v0, 0x493

    const/16 v2, 0x492

    const/4 v3, 0x1

    if-eq v1, v2, :cond_8

    move v1, v3

    goto :goto_5

    :cond_8
    const/4 v1, 0x0

    :goto_5
    and-int/2addr v0, v3

    invoke-virtual {p4, v0, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_9

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/o58;

    new-instance v1, Llyiahf/vczjk/lt4;

    invoke-direct {v1, p2, p3, p0}, Llyiahf/vczjk/lt4;-><init>(ILjava/lang/Object;Llyiahf/vczjk/nt4;)V

    const v2, 0x3a785bde

    invoke-static {v2, v1, p4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const/16 v2, 0x30

    invoke-interface {v0, p3, v1, p4, v2}, Llyiahf/vczjk/o58;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_6

    :cond_9
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p4

    if-eqz p4, :cond_a

    new-instance v0, Llyiahf/vczjk/mt4;

    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move-object v4, p3

    move v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/mt4;-><init>(Llyiahf/vczjk/nt4;Ljava/lang/Object;ILjava/lang/Object;I)V

    iput-object v0, p4, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_a
    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/iv3;Llyiahf/vczjk/kl5;Ljava/lang/Object;Llyiahf/vczjk/hv3;Llyiahf/vczjk/kd;Llyiahf/vczjk/rf1;I)V
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "modifier"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "imageOptions"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p5, Llyiahf/vczjk/zf1;

    const v0, 0x7717a7a1

    invoke-virtual {p5, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p5, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p6

    invoke-virtual {p5, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    invoke-virtual {p5, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x100

    goto :goto_2

    :cond_2
    const/16 v1, 0x80

    :goto_2
    or-int/2addr v0, v1

    invoke-virtual {p5, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    const/16 v1, 0x800

    goto :goto_3

    :cond_3
    const/16 v1, 0x400

    :goto_3
    or-int/2addr v0, v1

    invoke-virtual {p5, p4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x4000

    goto :goto_4

    :cond_4
    const/16 v1, 0x2000

    :goto_4
    or-int/2addr v0, v1

    and-int/lit16 v0, v0, 0x2493

    const/16 v1, 0x2492

    if-ne v0, v1, :cond_6

    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_6
    :goto_5
    iget-object v0, p0, Llyiahf/vczjk/iv3;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_7

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    goto :goto_6

    :cond_7
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_9

    :goto_7
    invoke-virtual {p5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p5

    if-eqz p5, :cond_8

    new-instance v0, Llyiahf/vczjk/nu3;

    const/4 v7, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move v6, p6

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/nu3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p5, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void

    :cond_9
    invoke-static {v0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/jl5;
    .locals 2

    check-cast p0, Llyiahf/vczjk/jl5;

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez p0, :cond_0

    goto :goto_1

    :cond_0
    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/2addr v0, p1

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    if-eqz p0, :cond_4

    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, v0, 0x2

    if-eqz v1, :cond_2

    goto :goto_1

    :cond_2
    and-int/2addr v0, p1

    if-eqz v0, :cond_3

    return-object p0

    :cond_3
    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_4
    :goto_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooO0oo(Ljava/lang/Object;)Ljava/util/Map;
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/cg4;

    if-eqz v0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/fg4;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const-string v0, "kotlin.collections.MutableMap"

    invoke-static {p0, v0}, Llyiahf/vczjk/l4a;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0

    :cond_1
    :goto_0
    :try_start_0
    check-cast p0, Ljava/util/Map;
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    const-class v0, Llyiahf/vczjk/l4a;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->Oooooo(Ljava/lang/RuntimeException;Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOO0(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 2

    if-eqz p1, :cond_1

    invoke-static {p0, p1}, Llyiahf/vczjk/l4a;->OooOooO(ILjava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "kotlin.jvm.functions.Function"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Llyiahf/vczjk/l4a;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0

    :cond_1
    :goto_0
    return-object p1
.end method

.method public static OooOO0O(JLlyiahf/vczjk/rf1;I)Llyiahf/vczjk/sq0;
    .locals 20

    invoke-static/range {p0 .. p2}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide v0

    sget-wide v2, Llyiahf/vczjk/n21;->OooOO0:J

    const v4, 0x3ec28f5c    # 0.38f

    invoke-static {v4, v0, v1}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v4

    sget-object v6, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/x21;

    invoke-static {v6}, Llyiahf/vczjk/l4a;->OooOo0o(Llyiahf/vczjk/x21;)Llyiahf/vczjk/sq0;

    move-result-object v6

    const-wide/16 v7, 0x10

    cmp-long v9, p0, v7

    if-eqz v9, :cond_0

    move-wide/from16 v12, p0

    goto :goto_0

    :cond_0
    iget-wide v9, v6, Llyiahf/vczjk/sq0;->OooO00o:J

    move-wide v12, v9

    :goto_0
    cmp-long v9, v0, v7

    if-eqz v9, :cond_1

    :goto_1
    move-wide v14, v0

    goto :goto_2

    :cond_1
    iget-wide v0, v6, Llyiahf/vczjk/sq0;->OooO0O0:J

    goto :goto_1

    :goto_2
    cmp-long v0, v2, v7

    if-eqz v0, :cond_2

    :goto_3
    move-wide/from16 v16, v2

    goto :goto_4

    :cond_2
    iget-wide v2, v6, Llyiahf/vczjk/sq0;->OooO0OO:J

    goto :goto_3

    :goto_4
    cmp-long v0, v4, v7

    if-eqz v0, :cond_3

    :goto_5
    move-wide/from16 v18, v4

    goto :goto_6

    :cond_3
    iget-wide v4, v6, Llyiahf/vczjk/sq0;->OooO0Oo:J

    goto :goto_5

    :goto_6
    new-instance v11, Llyiahf/vczjk/sq0;

    invoke-direct/range {v11 .. v19}, Llyiahf/vczjk/sq0;-><init>(JJJJ)V

    return-object v11
.end method

.method public static OooOO0o()Llyiahf/vczjk/vq0;
    .locals 7

    sget v1, Llyiahf/vczjk/n03;->OooO0O0:F

    sget v2, Llyiahf/vczjk/n03;->OooOO0:F

    sget v3, Llyiahf/vczjk/n03;->OooO0oo:F

    sget v4, Llyiahf/vczjk/n03;->OooO:F

    sget v5, Llyiahf/vczjk/n03;->OooO0oO:F

    sget v6, Llyiahf/vczjk/n03;->OooO0o0:F

    new-instance v0, Llyiahf/vczjk/vq0;

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/vq0;-><init>(FFFFFF)V

    return-object v0
.end method

.method public static OooOOO(FFF)F
    .locals 1

    cmpg-float v0, p0, p1

    if-gez v0, :cond_0

    return p1

    :cond_0
    cmpl-float p1, p0, p2

    if-lez p1, :cond_1

    return p2

    :cond_1
    return p0
.end method

.method public static OooOOO0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/py0;Llyiahf/vczjk/cm7;I)Llyiahf/vczjk/ld9;
    .locals 3

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    :cond_0
    const-string p3, "<this>"

    invoke-static {p0, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p3, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/o0O000;

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-direct {v0, v1, p0, p1, v2}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-static {p3, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p3

    iget-object v0, p0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    if-eqz p2, :cond_1

    new-instance v1, Llyiahf/vczjk/rr0;

    const/4 v2, 0x0

    invoke-direct {v1, p0, p1, p2, v2}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/x02;Llyiahf/vczjk/e74;I)V

    goto :goto_0

    :cond_1
    iget-object p0, p0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/v4a;

    :goto_0
    new-instance p0, Llyiahf/vczjk/ld9;

    invoke-direct {p0, v0, v1, p3}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    return-object p0
.end method

.method public static OooOOOO(III)I
    .locals 0

    if-ge p0, p1, :cond_0

    return p1

    :cond_0
    if-le p0, p2, :cond_1

    return p2

    :cond_1
    return p0
.end method

.method public static final OooOOOo(JLlyiahf/vczjk/zj2;Llyiahf/vczjk/zj2;)J
    .locals 1

    const-string v0, "sourceUnit"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "targetUnit"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p3}, Llyiahf/vczjk/zj2;->OooO00o()Ljava/util/concurrent/TimeUnit;

    move-result-object p3

    invoke-virtual {p2}, Llyiahf/vczjk/zj2;->OooO00o()Ljava/util/concurrent/TimeUnit;

    move-result-object p2

    invoke-virtual {p3, p0, p1, p2}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOOo(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ko;)Llyiahf/vczjk/ld9;
    .locals 5

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "additionalAnnotations"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/ko;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ld9;

    sget-object v1, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v2, Llyiahf/vczjk/o0O000;

    const/4 v3, 0x7

    const/4 v4, 0x0

    invoke-direct {v2, v3, p0, p1, v4}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-static {v1, v2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object p0, p0, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/v4a;

    invoke-direct {v0, v1, p0, p1}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    return-object v0
.end method

.method public static final OooOOo0(JLlyiahf/vczjk/zj2;Llyiahf/vczjk/zj2;)J
    .locals 1

    const-string v0, "sourceUnit"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "targetUnit"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p3}, Llyiahf/vczjk/zj2;->OooO00o()Ljava/util/concurrent/TimeUnit;

    move-result-object p3

    invoke-virtual {p2}, Llyiahf/vczjk/zj2;->OooO00o()Ljava/util/concurrent/TimeUnit;

    move-result-object p2

    invoke-virtual {p3, p0, p1, p2}, Ljava/util/concurrent/TimeUnit;->convert(JLjava/util/concurrent/TimeUnit;)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOOoo(Llyiahf/vczjk/lq5;Llyiahf/vczjk/eq0;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V
    .locals 10

    iget-object p0, p0, Llyiahf/vczjk/lq5;->OooO0oo:Ljava/util/ArrayList;

    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/bo6;

    iget-object v3, v2, Llyiahf/vczjk/bo6;->OooO00o:Llyiahf/vczjk/le;

    move-object v4, p1

    move-object v5, p2

    move v6, p3

    move-object v7, p4

    move-object v8, p5

    move-object/from16 v9, p6

    invoke-virtual/range {v3 .. v9}, Llyiahf/vczjk/le;->OooO0oO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V

    iget-object v2, v2, Llyiahf/vczjk/bo6;->OooO00o:Llyiahf/vczjk/le;

    invoke-virtual {v2}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v2

    const/4 v3, 0x0

    invoke-interface {p1, v3, v2}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public static final OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1}, Llyiahf/vczjk/rt5;->Oooo(I)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo0(Landroidx/appcompat/widget/Toolbar;)Landroidx/appcompat/widget/ActionMenuView;
    .locals 3

    const/4 v0, 0x0

    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v1

    if-ge v0, v1, :cond_1

    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    instance-of v2, v1, Landroidx/appcompat/widget/ActionMenuView;

    if-eqz v2, :cond_0

    check-cast v1, Landroidx/appcompat/widget/ActionMenuView;

    return-object v1

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOo00(Landroid/content/Context;Llyiahf/vczjk/oe3;)Ljava/io/File;
    .locals 12

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/io/File;

    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v1

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    const-string v4, "Thanox-Log-"

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/u81;->OooO(JLjava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroid/content/Context;->getExternalCacheDir()Ljava/io/File;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {p0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v1

    :cond_0
    if-eqz v1, :cond_8

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    invoke-static {v2, v3}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatForFileName(J)Ljava/lang/String;

    move-result-object v2

    const-string v3, ".zip"

    invoke-static {v4, v2, v3}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    new-instance v3, Ljava/io/File;

    invoke-static {p0}, Llyiahf/vczjk/c6a;->OoooO(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v3, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    sget-object p0, Llyiahf/vczjk/md1;->OooOOo:Llyiahf/vczjk/md1;

    invoke-virtual {v3}, Ljava/io/File;->exists()Z

    move-result v4

    const-string v5, "The source file doesn\'t exist."

    const/4 v6, 0x0

    if-eqz v4, :cond_7

    :try_start_0
    sget-object v4, Llyiahf/vczjk/b03;->OooOOO0:Llyiahf/vczjk/b03;

    new-instance v7, Llyiahf/vczjk/uu;

    const/4 v8, 0x1

    invoke-direct {v7, p0, v8}, Llyiahf/vczjk/uu;-><init>(Llyiahf/vczjk/ze3;I)V

    new-instance v8, Llyiahf/vczjk/oz2;

    invoke-direct {v8, v3, v4, v7}, Llyiahf/vczjk/oz2;-><init>(Ljava/io/File;Llyiahf/vczjk/b03;Llyiahf/vczjk/uu;)V

    new-instance v4, Llyiahf/vczjk/mz2;

    invoke-direct {v4, v8}, Llyiahf/vczjk/mz2;-><init>(Llyiahf/vczjk/oz2;)V

    :goto_0
    invoke-virtual {v4}, Llyiahf/vczjk/o0O0ooO;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-virtual {v4}, Llyiahf/vczjk/o0O0ooO;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/io/File;

    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    move-result v8

    if-eqz v8, :cond_5

    invoke-static {v7, v3}, Llyiahf/vczjk/d03;->o00O0O(Ljava/io/File;Ljava/io/File;)Ljava/lang/String;

    move-result-object v8

    new-instance v9, Ljava/io/File;

    invoke-direct {v9, v0, v8}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v9}, Ljava/io/File;->exists()Z

    move-result v8

    if-eqz v8, :cond_2

    invoke-virtual {v7}, Ljava/io/File;->isDirectory()Z

    move-result v8

    if-eqz v8, :cond_1

    invoke-virtual {v9}, Ljava/io/File;->isDirectory()Z

    move-result v8

    if-eqz v8, :cond_1

    goto :goto_1

    :cond_1
    new-instance v3, Llyiahf/vczjk/o0O00;

    const-string v4, "The destination file already exists."

    invoke-direct {v3, v7, v9, v4}, Llyiahf/vczjk/fz2;-><init>(Ljava/io/File;Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0, v9, v3}, Llyiahf/vczjk/md1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    throw v6

    :cond_2
    :goto_1
    invoke-virtual {v7}, Ljava/io/File;->isDirectory()Z

    move-result v8

    if-eqz v8, :cond_3

    invoke-virtual {v9}, Ljava/io/File;->mkdirs()Z

    goto :goto_0

    :cond_3
    const/4 v8, 0x0

    invoke-static {v7, v9, v8}, Llyiahf/vczjk/d03;->OooooOo(Ljava/io/File;Ljava/io/File;Z)V

    invoke-virtual {v9}, Ljava/io/File;->length()J

    move-result-wide v8

    invoke-virtual {v7}, Ljava/io/File;->length()J

    move-result-wide v10

    cmp-long v8, v8, v10

    if-nez v8, :cond_4

    goto :goto_0

    :cond_4
    new-instance v3, Ljava/io/IOException;

    const-string v4, "Source file wasn\'t copied completely, length of destination file differs."

    invoke-direct {v3, v4}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v7, v3}, Llyiahf/vczjk/md1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    throw v6

    :cond_5
    new-instance v3, Llyiahf/vczjk/o0O00;

    invoke-direct {v3, v7, v6, v5}, Llyiahf/vczjk/fz2;-><init>(Ljava/io/File;Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0, v7, v3}, Llyiahf/vczjk/md1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    throw v6
    :try_end_0
    .catch Llyiahf/vczjk/yg9; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_6
    new-instance p0, Ljava/io/File;

    const-string v3, "service.zip"

    invoke-direct {p0, v0, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/io/File;->createNewFile()Z

    const/high16 v3, 0x30000000

    invoke-static {p0, v3}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p1, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    invoke-static {p0, p1, v2}, Lgithub/tornaco/android/thanos/core/util/ZipUtils;->zip(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/d03;->Oooooo0(Ljava/io/File;)Z

    new-instance p0, Ljava/io/File;

    invoke-direct {p0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    return-object p0

    :cond_7
    new-instance p1, Llyiahf/vczjk/o0O00;

    invoke-direct {p1, v3, v6, v5}, Llyiahf/vczjk/fz2;-><init>(Ljava/io/File;Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p0, v3, p1}, Llyiahf/vczjk/md1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    throw v6

    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "context.cache is null"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1}, Llyiahf/vczjk/rt5;->OooO0Oo(I)Ljava/lang/String;

    move-result-object v0

    invoke-interface {p0, p1}, Llyiahf/vczjk/rt5;->OooooOo(I)Z

    move-result p0

    invoke-static {v0, p0}, Llyiahf/vczjk/jp8;->OooOo0o(Ljava/lang/String;Z)Llyiahf/vczjk/hy0;

    move-result-object p0

    return-object p0
.end method

.method public static OooOo0o(Llyiahf/vczjk/x21;)Llyiahf/vczjk/sq0;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/x21;->OoooOoo:Llyiahf/vczjk/sq0;

    if-nez v0, :cond_0

    new-instance v1, Llyiahf/vczjk/sq0;

    sget-object v0, Llyiahf/vczjk/n03;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {p0, v0}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v2

    invoke-static {p0, v0}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v4

    invoke-static {p0, v4, v5}, Llyiahf/vczjk/z21;->OooO00o(Llyiahf/vczjk/x21;J)J

    move-result-wide v4

    sget-object v6, Llyiahf/vczjk/n03;->OooO0Oo:Llyiahf/vczjk/y21;

    invoke-static {p0, v6}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v6

    sget v8, Llyiahf/vczjk/n03;->OooO0o:F

    invoke-static {v8, v6, v7}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v6

    invoke-static {p0, v0}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v8

    invoke-static {v6, v7, v8, v9}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v6

    invoke-static {p0, v0}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v8

    invoke-static {p0, v8, v9}, Llyiahf/vczjk/z21;->OooO00o(Llyiahf/vczjk/x21;J)J

    move-result-wide v8

    const v0, 0x3ec28f5c    # 0.38f

    invoke-static {v0, v8, v9}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v8

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/sq0;-><init>(JJJJ)V

    iput-object v1, p0, Llyiahf/vczjk/x21;->OoooOoo:Llyiahf/vczjk/sq0;

    return-object v1

    :cond_0
    return-object v0
.end method

.method public static OooOoO(I)Ljava/lang/String;
    .locals 2

    const/4 v0, 0x2

    if-eq p0, v0, :cond_5

    const/4 v1, 0x3

    if-eq p0, v1, :cond_4

    const/4 v1, 0x4

    if-eq p0, v1, :cond_3

    const/4 v1, 0x5

    if-eq p0, v1, :cond_2

    const/4 v1, 0x6

    if-eq p0, v1, :cond_1

    if-ge p0, v0, :cond_0

    sub-int/2addr v0, p0

    const-string p0, "V-"

    invoke-static {v0, p0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    sub-int/2addr p0, v1

    const-string v0, "E+"

    invoke-static {p0, v0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_1
    const-string p0, "E"

    return-object p0

    :cond_2
    const-string p0, "W"

    return-object p0

    :cond_3
    const-string p0, "I"

    return-object p0

    :cond_4
    const-string p0, "D"

    return-object p0

    :cond_5
    const-string p0, "V"

    return-object p0
.end method

.method public static OooOoO0(Landroidx/appcompat/widget/Toolbar;)Landroid/widget/ImageButton;
    .locals 5

    invoke-virtual {p0}, Landroidx/appcompat/widget/Toolbar;->getNavigationIcon()Landroid/graphics/drawable/Drawable;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    const/4 v2, 0x0

    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v3

    if-ge v2, v3, :cond_2

    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    instance-of v4, v3, Landroid/widget/ImageButton;

    if-eqz v4, :cond_1

    check-cast v3, Landroid/widget/ImageButton;

    invoke-virtual {v3}, Landroid/widget/ImageView;->getDrawable()Landroid/graphics/drawable/Drawable;

    move-result-object v4

    if-ne v4, v0, :cond_1

    return-object v3

    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    return-object v1
.end method

.method public static OooOoOO(Lcom/google/android/material/appbar/MaterialToolbar;Ljava/lang/CharSequence;)Ljava/util/ArrayList;
    .locals 4

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    const/4 v1, 0x0

    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v2

    if-ge v1, v2, :cond_1

    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v2

    instance-of v3, v2, Landroid/widget/TextView;

    if-eqz v3, :cond_0

    check-cast v2, Landroid/widget/TextView;

    invoke-virtual {v2}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    move-result-object v3

    invoke-static {v3, p1}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method public static OooOoo(F)I
    .locals 15

    const/high16 v0, 0x3f800000    # 1.0f

    cmpg-float v0, p0, v0

    if-gez v0, :cond_0

    const/high16 p0, -0x1000000

    return p0

    :cond_0
    const/high16 v0, 0x42c60000    # 99.0f

    cmpl-float v0, p0, v0

    if-lez v0, :cond_1

    const/4 p0, -0x1

    return p0

    :cond_1
    const/high16 v0, 0x41800000    # 16.0f

    add-float v1, p0, v0

    const/high16 v2, 0x42e80000    # 116.0f

    div-float/2addr v1, v2

    const/high16 v3, 0x41000000    # 8.0f

    cmpl-float v3, p0, v3

    const v4, 0x4461d2f7

    if-lez v3, :cond_2

    mul-float p0, v1, v1

    mul-float/2addr p0, v1

    goto :goto_0

    :cond_2
    div-float/2addr p0, v4

    :goto_0
    mul-float v3, v1, v1

    mul-float/2addr v3, v1

    const v5, 0x3c111aa7

    cmpl-float v5, v3, v5

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-lez v5, :cond_3

    move v5, v7

    goto :goto_1

    :cond_3
    move v5, v6

    :goto_1
    if-eqz v5, :cond_4

    move v8, v3

    goto :goto_2

    :cond_4
    mul-float v8, v1, v2

    sub-float/2addr v8, v0

    div-float/2addr v8, v4

    :goto_2
    if-eqz v5, :cond_5

    goto :goto_3

    :cond_5
    mul-float/2addr v1, v2

    sub-float/2addr v1, v0

    div-float v3, v1, v4

    :goto_3
    sget-object v0, Llyiahf/vczjk/l4a;->OooO0OO:[F

    aget v1, v0, v6

    mul-float/2addr v8, v1

    float-to-double v9, v8

    aget v1, v0, v7

    mul-float/2addr p0, v1

    float-to-double v11, p0

    const/4 p0, 0x2

    aget p0, v0, p0

    mul-float/2addr v3, p0

    float-to-double v13, v3

    invoke-static/range {v9 .. v14}, Llyiahf/vczjk/h31;->OooO00o(DDD)I

    move-result p0

    return p0
.end method

.method public static final OooOoo0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/gz0;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    instance-of p0, p0, Llyiahf/vczjk/hh6;

    if-eqz p0, :cond_0

    return-object v1

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    instance-of p0, p0, Llyiahf/vczjk/hh6;

    if-nez p0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/l4a;->OooOoo0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/gz0;

    move-result-object p0

    return-object p0

    :cond_1
    instance-of p0, v0, Llyiahf/vczjk/gz0;

    if-eqz p0, :cond_2

    check-cast v0, Llyiahf/vczjk/gz0;

    return-object v0

    :cond_2
    return-object v1
.end method

.method public static OooOooO(ILjava/lang/Object;)Z
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/cf3;

    const/4 v1, 0x0

    if-eqz v0, :cond_18

    instance-of v0, p1, Llyiahf/vczjk/lf3;

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/lf3;

    invoke-interface {p1}, Llyiahf/vczjk/lf3;->getArity()I

    move-result p1

    goto/16 :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/le3;

    if-eqz v0, :cond_1

    move p1, v1

    goto/16 :goto_0

    :cond_1
    instance-of v0, p1, Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_2

    move p1, v2

    goto/16 :goto_0

    :cond_2
    instance-of v0, p1, Llyiahf/vczjk/ze3;

    if-eqz v0, :cond_3

    const/4 p1, 0x2

    goto/16 :goto_0

    :cond_3
    instance-of v0, p1, Llyiahf/vczjk/bf3;

    if-eqz v0, :cond_4

    const/4 p1, 0x3

    goto/16 :goto_0

    :cond_4
    instance-of v0, p1, Llyiahf/vczjk/df3;

    if-eqz v0, :cond_5

    const/4 p1, 0x4

    goto/16 :goto_0

    :cond_5
    instance-of v0, p1, Llyiahf/vczjk/ef3;

    if-eqz v0, :cond_6

    const/4 p1, 0x5

    goto/16 :goto_0

    :cond_6
    instance-of v0, p1, Llyiahf/vczjk/ff3;

    if-eqz v0, :cond_7

    const/4 p1, 0x6

    goto/16 :goto_0

    :cond_7
    instance-of v0, p1, Llyiahf/vczjk/gf3;

    if-eqz v0, :cond_8

    const/4 p1, 0x7

    goto/16 :goto_0

    :cond_8
    instance-of v0, p1, Llyiahf/vczjk/hf3;

    if-eqz v0, :cond_9

    const/16 p1, 0x8

    goto/16 :goto_0

    :cond_9
    instance-of v0, p1, Llyiahf/vczjk/if3;

    if-eqz v0, :cond_a

    const/16 p1, 0x9

    goto/16 :goto_0

    :cond_a
    instance-of v0, p1, Llyiahf/vczjk/me3;

    if-eqz v0, :cond_b

    const/16 p1, 0xa

    goto :goto_0

    :cond_b
    instance-of v0, p1, Llyiahf/vczjk/ne3;

    if-eqz v0, :cond_c

    const/16 p1, 0xb

    goto :goto_0

    :cond_c
    instance-of v0, p1, Llyiahf/vczjk/eg3;

    if-eqz v0, :cond_d

    const/16 p1, 0xc

    goto :goto_0

    :cond_d
    instance-of v3, p1, Llyiahf/vczjk/pe3;

    if-eqz v3, :cond_e

    const/16 p1, 0xd

    goto :goto_0

    :cond_e
    instance-of v3, p1, Llyiahf/vczjk/qe3;

    if-eqz v3, :cond_f

    const/16 p1, 0xe

    goto :goto_0

    :cond_f
    instance-of v3, p1, Llyiahf/vczjk/re3;

    if-eqz v3, :cond_10

    const/16 p1, 0xf

    goto :goto_0

    :cond_10
    instance-of v3, p1, Llyiahf/vczjk/se3;

    if-eqz v3, :cond_11

    const/16 p1, 0x10

    goto :goto_0

    :cond_11
    instance-of v3, p1, Llyiahf/vczjk/te3;

    if-eqz v3, :cond_12

    const/16 p1, 0x11

    goto :goto_0

    :cond_12
    instance-of v3, p1, Llyiahf/vczjk/ue3;

    if-eqz v3, :cond_13

    const/16 p1, 0x12

    goto :goto_0

    :cond_13
    instance-of v3, p1, Llyiahf/vczjk/ve3;

    if-eqz v3, :cond_14

    const/16 p1, 0x13

    goto :goto_0

    :cond_14
    instance-of v3, p1, Llyiahf/vczjk/xe3;

    if-eqz v3, :cond_15

    const/16 p1, 0x14

    goto :goto_0

    :cond_15
    instance-of p1, p1, Llyiahf/vczjk/ye3;

    if-eqz p1, :cond_16

    const/16 p1, 0x15

    goto :goto_0

    :cond_16
    if-eqz v0, :cond_17

    const/16 p1, 0x16

    goto :goto_0

    :cond_17
    const/4 p1, -0x1

    :goto_0
    if-ne p1, p0, :cond_18

    return v2

    :cond_18
    return v1
.end method

.method public static OooOooo(I)F
    .locals 6

    int-to-float p0, p0

    const/high16 v0, 0x437f0000    # 255.0f

    div-float/2addr p0, v0

    const v0, 0x3d25aee6    # 0.04045f

    cmpg-float v0, p0, v0

    const/high16 v1, 0x42c80000    # 100.0f

    if-gtz v0, :cond_0

    const v0, 0x414eb852    # 12.92f

    div-float/2addr p0, v0

    :goto_0
    mul-float/2addr p0, v1

    return p0

    :cond_0
    const v0, 0x3d6147ae    # 0.055f

    add-float/2addr p0, v0

    const v0, 0x3f870a3d    # 1.055f

    div-float/2addr p0, v0

    float-to-double v2, p0

    const-wide v4, 0x4003333340000000L    # 2.4000000953674316

    invoke-static {v2, v3, v4, v5}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v2

    double-to-float p0, v2

    goto :goto_0
.end method

.method public static Oooo0(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;)V
    .locals 12

    const/16 v0, 0x800

    const/4 v1, 0x0

    const/4 v2, 0x1

    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1e

    if-lt v3, v4, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/o0O0o00O;->OooOO0O(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;)V

    return-void

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-lt v3, v4, :cond_1

    invoke-static {p0, p1}, Llyiahf/vczjk/o0O0o00O;->OooOO0O(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;)V

    return-void

    :cond_1
    iget v3, p0, Landroid/view/inputmethod/EditorInfo;->initialSelStart:I

    iget v4, p0, Landroid/view/inputmethod/EditorInfo;->initialSelEnd:I

    if-le v3, v4, :cond_2

    move v5, v4

    goto :goto_0

    :cond_2
    move v5, v3

    :goto_0
    if-le v3, v4, :cond_3

    goto :goto_1

    :cond_3
    move v3, v4

    :goto_1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v4

    const/4 v6, 0x0

    if-ltz v5, :cond_c

    if-le v3, v4, :cond_4

    goto/16 :goto_5

    :cond_4
    iget v7, p0, Landroid/view/inputmethod/EditorInfo;->inputType:I

    and-int/lit16 v7, v7, 0xfff

    const/16 v8, 0x81

    if-eq v7, v8, :cond_b

    const/16 v8, 0xe1

    if-eq v7, v8, :cond_b

    const/16 v8, 0x12

    if-ne v7, v8, :cond_5

    goto :goto_4

    :cond_5
    if-gt v4, v0, :cond_6

    invoke-static {p0, p1, v5, v3}, Llyiahf/vczjk/l4a;->Oooo0OO(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;II)V

    return-void

    :cond_6
    sub-int v4, v3, v5

    const/16 v6, 0x400

    if-le v4, v6, :cond_7

    move v6, v1

    goto :goto_2

    :cond_7
    move v6, v4

    :goto_2
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v7

    sub-int/2addr v7, v3

    sub-int/2addr v0, v6

    const-wide v8, 0x3fe999999999999aL    # 0.8

    int-to-double v10, v0

    mul-double/2addr v10, v8

    double-to-int v8, v10

    invoke-static {v5, v8}, Ljava/lang/Math;->min(II)I

    move-result v8

    sub-int v8, v0, v8

    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    move-result v7

    sub-int/2addr v0, v7

    invoke-static {v5, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    sub-int/2addr v5, v0

    invoke-interface {p1, v5}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v8

    invoke-static {v8}, Ljava/lang/Character;->isLowSurrogate(C)Z

    move-result v8

    if-eqz v8, :cond_8

    add-int/2addr v5, v2

    sub-int/2addr v0, v2

    :cond_8
    add-int v8, v3, v7

    sub-int/2addr v8, v2

    invoke-interface {p1, v8}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v8

    invoke-static {v8}, Ljava/lang/Character;->isHighSurrogate(C)Z

    move-result v8

    if-eqz v8, :cond_9

    sub-int/2addr v7, v2

    :cond_9
    add-int v8, v0, v6

    add-int v9, v8, v7

    if-eq v6, v4, :cond_a

    add-int v4, v5, v0

    invoke-interface {p1, v5, v4}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object v4

    add-int/2addr v7, v3

    invoke-interface {p1, v3, v7}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object p1

    const/4 v3, 0x2

    new-array v3, v3, [Ljava/lang/CharSequence;

    aput-object v4, v3, v1

    aput-object p1, v3, v2

    invoke-static {v3}, Landroid/text/TextUtils;->concat([Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p1

    goto :goto_3

    :cond_a
    add-int/2addr v9, v5

    invoke-interface {p1, v5, v9}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    move-result-object p1

    :goto_3
    invoke-static {p0, p1, v0, v8}, Llyiahf/vczjk/l4a;->Oooo0OO(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;II)V

    return-void

    :cond_b
    :goto_4
    invoke-static {p0, v6, v1, v1}, Llyiahf/vczjk/l4a;->Oooo0OO(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;II)V

    return-void

    :cond_c
    :goto_5
    invoke-static {p0, v6, v1, v1}, Llyiahf/vczjk/l4a;->Oooo0OO(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;II)V

    return-void
.end method

.method public static final Oooo000(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/zf1;)Llyiahf/vczjk/yg5;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p4

    move-object/from16 v2, p5

    const-string v3, "appInfo"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "setMode"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const v3, -0x1f041f21

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v3, 0x4c5de2

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v4, :cond_0

    if-ne v5, v6, :cond_1

    :cond_0
    new-instance v5, Llyiahf/vczjk/o000OO;

    const/16 v4, 0x8

    invoke-direct {v5, v0, v4}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v5, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v4, 0xa

    if-eqz p1, :cond_5

    const v7, -0x609c6f00

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v7, Lgithub/tornaco/android/thanos/core/ops/PermState;->ALLOW_ALWAYS:Lgithub/tornaco/android/thanos/core/ops/PermState;

    const/4 v8, 0x0

    if-eqz p2, :cond_2

    sget-object v9, Lgithub/tornaco/android/thanos/core/ops/PermState;->ALLOW_FOREGROUND_ONLY:Lgithub/tornaco/android/thanos/core/ops/PermState;

    goto :goto_0

    :cond_2
    move-object v9, v8

    :goto_0
    if-eqz p3, :cond_3

    sget-object v8, Lgithub/tornaco/android/thanos/core/ops/PermState;->ASK:Lgithub/tornaco/android/thanos/core/ops/PermState;

    :cond_3
    sget-object v10, Lgithub/tornaco/android/thanos/core/ops/PermState;->IGNORE:Lgithub/tornaco/android/thanos/core/ops/PermState;

    sget-object v11, Lgithub/tornaco/android/thanos/core/ops/PermState;->DENY:Lgithub/tornaco/android/thanos/core/ops/PermState;

    filled-new-array {v7, v9, v8, v10, v11}, [Lgithub/tornaco/android/thanos/core/ops/PermState;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/sy;->o0OO00O([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v7

    new-instance v8, Ljava/util/ArrayList;

    invoke-static {v7, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v8, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Lgithub/tornaco/android/thanos/core/ops/PermState;

    new-instance v9, Llyiahf/vczjk/wg5;

    invoke-virtual {v7}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v10

    invoke-static {v7, v2}, Llyiahf/vczjk/vr3;->OooO0O0(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object v11

    invoke-static {v7, v2}, Llyiahf/vczjk/vr3;->OooO0OO(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object v12

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v15, 0x18

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_5
    const v7, -0x6094a96e

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v7, Lgithub/tornaco/android/thanos/core/ops/PermState;->ALLOW_ALWAYS:Lgithub/tornaco/android/thanos/core/ops/PermState;

    sget-object v8, Lgithub/tornaco/android/thanos/core/ops/PermState;->IGNORE:Lgithub/tornaco/android/thanos/core/ops/PermState;

    filled-new-array {v7, v8}, [Lgithub/tornaco/android/thanos/core/ops/PermState;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v7

    new-instance v8, Ljava/util/ArrayList;

    invoke-static {v7, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v8, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Lgithub/tornaco/android/thanos/core/ops/PermState;

    new-instance v9, Llyiahf/vczjk/wg5;

    invoke-virtual {v7}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v10

    invoke-static {v7, v2}, Llyiahf/vczjk/vr3;->OooO0O0(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object v11

    invoke-static {v7, v2}, Llyiahf/vczjk/vr3;->OooO0OO(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object v12

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v15, 0x18

    invoke-direct/range {v9 .. v15}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_6
    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_7

    if-ne v4, v6, :cond_8

    :cond_7
    new-instance v4, Llyiahf/vczjk/uu;

    const/4 v3, 0x0

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/uu;-><init>(Llyiahf/vczjk/ze3;I)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x2

    invoke-static {v1, v8, v2, v5, v4}, Llyiahf/vczjk/rs;->o000oOoO(ILjava/util/List;Llyiahf/vczjk/rf1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yg5;

    move-result-object v1

    const/16 v3, 0x8

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v1
.end method

.method public static Oooo00O(Ljava/io/InputStream;)Llyiahf/vczjk/ck0;
    .locals 3

    new-instance v0, Ljava/io/DataInputStream;

    invoke-direct {v0, p0}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    new-instance p0, Llyiahf/vczjk/x14;

    invoke-virtual {v0}, Ljava/io/DataInputStream;->readInt()I

    move-result v1

    const/4 v2, 0x1

    invoke-direct {p0, v2, v1, v2}, Llyiahf/vczjk/v14;-><init>(III)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {p0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {p0}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object p0

    :goto_0
    iget-boolean v2, p0, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz v2, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/n14;->OooO00o()I

    invoke-virtual {v0}, Ljava/io/DataInputStream;->readInt()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000O0O(Ljava/util/List;)[I

    move-result-object p0

    array-length v0, p0

    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object p0

    new-instance v0, Llyiahf/vczjk/ck0;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ck0;-><init>([I)V

    return-object v0
.end method

.method public static final Oooo00o(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;
    .locals 5

    sget-object v0, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    const-string v1, "<this>"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "fqName"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    invoke-virtual {p0, v2}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/hw4;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v4

    iget-object v2, v2, Llyiahf/vczjk/hw4;->OooOo0O:Llyiahf/vczjk/pw4;

    invoke-virtual {v2, v4, v0}, Llyiahf/vczjk/pw4;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v2

    instance-of v4, v2, Llyiahf/vczjk/by0;

    if-eqz v4, :cond_1

    check-cast v2, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_1
    move-object v2, v3

    :goto_0
    if-eqz v2, :cond_2

    return-object v2

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/l4a;->Oooo00o(Llyiahf/vczjk/dm5;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-interface {p0}, Llyiahf/vczjk/by0;->o0ooOO0()Llyiahf/vczjk/jg5;

    move-result-object p0

    if-eqz p0, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-interface {p0, p1, v0}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p0

    goto :goto_1

    :cond_3
    move-object p0, v3

    :goto_1
    instance-of p1, p0, Llyiahf/vczjk/by0;

    if-eqz p1, :cond_4

    check-cast p0, Llyiahf/vczjk/by0;

    return-object p0

    :cond_4
    :goto_2
    return-object v3
.end method

.method public static Oooo0O0(Landroid/view/inputmethod/EditorInfo;Z)V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x23

    if-lt v0, v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/ct1;->OooO0Oo(Landroid/view/inputmethod/EditorInfo;Z)V

    :cond_0
    iget-object v0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    if-nez v0, :cond_1

    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    iput-object v0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    :cond_1
    iget-object p0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    const-string v0, "androidx.core.view.inputmethod.EditorInfoCompat.STYLUS_HANDWRITING_ENABLED"

    invoke-virtual {p0, v0, p1}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    return-void
.end method

.method public static Oooo0OO(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;II)V
    .locals 2

    iget-object v0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    if-nez v0, :cond_0

    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    iput-object v0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    :cond_0
    if-eqz p1, :cond_1

    new-instance v0, Landroid/text/SpannableStringBuilder;

    invoke-direct {v0, p1}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    iget-object p1, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    const-string v1, "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SURROUNDING_TEXT"

    invoke-virtual {p1, v1, v0}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    iget-object p1, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    const-string v0, "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SELECTION_HEAD"

    invoke-virtual {p1, v0, p2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    iget-object p0, p0, Landroid/view/inputmethod/EditorInfo;->extras:Landroid/os/Bundle;

    const-string p1, "androidx.core.view.inputmethod.EditorInfoCompat.CONTENT_SELECTION_END"

    invoke-virtual {p0, p1, p3}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    return-void
.end method

.method public static final Oooo0o(Ljava/lang/Object;Llyiahf/vczjk/bi3;)Llyiahf/vczjk/kd;
    .locals 1

    const-string v0, "glideRequestType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_2

    const/4 v0, 0x1

    if-eq p1, v0, :cond_1

    const/4 v0, 0x2

    if-ne p1, v0, :cond_0

    check-cast p0, Lcom/bumptech/glide/load/resource/gif/GifDrawable;

    invoke-virtual {p0}, Lcom/bumptech/glide/load/resource/gif/GifDrawable;->start()V

    invoke-static {p0}, Llyiahf/vczjk/vc6;->OoooO00(Landroid/graphics/drawable/Drawable;)Landroid/graphics/Bitmap;

    move-result-object p0

    new-instance p1, Llyiahf/vczjk/kd;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V

    return-object p1

    :cond_0
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_1
    check-cast p0, Landroid/graphics/Bitmap;

    new-instance p1, Llyiahf/vczjk/kd;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V

    return-object p1

    :cond_2
    check-cast p0, Landroid/graphics/drawable/Drawable;

    invoke-static {p0}, Llyiahf/vczjk/vc6;->OoooO00(Landroid/graphics/drawable/Drawable;)Landroid/graphics/Bitmap;

    move-result-object p0

    new-instance p1, Llyiahf/vczjk/kd;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V

    return-object p1
.end method

.method public static Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    if-nez p0, :cond_0

    const-string p0, "null"

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    :goto_0
    const-string v0, " cannot be cast to "

    invoke-static {p0, v0, p1}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1, p0}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    const-class p0, Llyiahf/vczjk/l4a;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->Oooooo(Ljava/lang/RuntimeException;Ljava/lang/String;)V

    throw p1
.end method

.method public static Oooo0oO()F
    .locals 4

    const/high16 v0, 0x42480000    # 50.0f

    float-to-double v0, v0

    const-wide/high16 v2, 0x4030000000000000L    # 16.0

    add-double/2addr v0, v2

    const-wide/high16 v2, 0x405d000000000000L    # 116.0

    div-double/2addr v0, v2

    const-wide/high16 v2, 0x4008000000000000L    # 3.0

    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v0

    double-to-float v0, v0

    const/high16 v1, 0x42c80000    # 100.0f

    mul-float/2addr v0, v1

    return v0
.end method
