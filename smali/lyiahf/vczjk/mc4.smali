.class public abstract Llyiahf/vczjk/mc4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/am;

.field public static final OooOOO0:Llyiahf/vczjk/zl;

.field public static final OooOOOO:Llyiahf/vczjk/bm;

.field public static final OooOOOo:Llyiahf/vczjk/cm;

.field public static final OooOOo:Llyiahf/vczjk/am;

.field public static final OooOOo0:Llyiahf/vczjk/zl;

.field public static final OooOOoo:Llyiahf/vczjk/bm;

.field public static final OooOo0:[Ljava/lang/reflect/Type;

.field public static final OooOo00:Llyiahf/vczjk/cm;

.field public static final OooOo0O:Llyiahf/vczjk/up3;

.field public static final OooOo0o:Llyiahf/vczjk/mm3;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/zl;

    const/high16 v1, 0x7f800000    # Float.POSITIVE_INFINITY

    invoke-direct {v0, v1}, Llyiahf/vczjk/zl;-><init>(F)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOO0:Llyiahf/vczjk/zl;

    new-instance v0, Llyiahf/vczjk/am;

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/am;-><init>(FF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOO:Llyiahf/vczjk/am;

    new-instance v0, Llyiahf/vczjk/bm;

    invoke-direct {v0, v1, v1, v1}, Llyiahf/vczjk/bm;-><init>(FFF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOOO:Llyiahf/vczjk/bm;

    new-instance v0, Llyiahf/vczjk/cm;

    invoke-direct {v0, v1, v1, v1, v1}, Llyiahf/vczjk/cm;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOOo:Llyiahf/vczjk/cm;

    new-instance v0, Llyiahf/vczjk/zl;

    const/high16 v1, -0x800000    # Float.NEGATIVE_INFINITY

    invoke-direct {v0, v1}, Llyiahf/vczjk/zl;-><init>(F)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOo0:Llyiahf/vczjk/zl;

    new-instance v0, Llyiahf/vczjk/am;

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/am;-><init>(FF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOo:Llyiahf/vczjk/am;

    new-instance v0, Llyiahf/vczjk/bm;

    invoke-direct {v0, v1, v1, v1}, Llyiahf/vczjk/bm;-><init>(FFF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOOoo:Llyiahf/vczjk/bm;

    new-instance v0, Llyiahf/vczjk/cm;

    invoke-direct {v0, v1, v1, v1, v1}, Llyiahf/vczjk/cm;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOo00:Llyiahf/vczjk/cm;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/reflect/Type;

    sput-object v0, Llyiahf/vczjk/mc4;->OooOo0:[Ljava/lang/reflect/Type;

    new-instance v0, Llyiahf/vczjk/up3;

    const/16 v1, 0x15

    invoke-direct {v0, v1}, Llyiahf/vczjk/up3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOo0O:Llyiahf/vczjk/up3;

    new-instance v0, Llyiahf/vczjk/mm3;

    const-string v1, "StdlibClassFinder"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/mm3;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/mc4;->OooOo0o:Llyiahf/vczjk/mm3;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/le3;JLlyiahf/vczjk/vk5;Llyiahf/vczjk/gi;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 22

    move-object/from16 v9, p4

    move-object/from16 v11, p5

    move/from16 v12, p7

    move-object/from16 v3, p6

    check-cast v3, Llyiahf/vczjk/zf1;

    const v0, 0x2db43478

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v12, 0x6

    move-object/from16 v6, p0

    if-nez v0, :cond_1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v12

    goto :goto_1

    :cond_1
    move v0, v12

    :goto_1
    and-int/lit8 v1, v12, 0x30

    move-wide/from16 v7, p1

    if-nez v1, :cond_3

    invoke-virtual {v3, v7, v8}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit16 v1, v12, 0x180

    move-object/from16 v10, p3

    if-nez v1, :cond_5

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x100

    goto :goto_3

    :cond_4
    const/16 v1, 0x80

    :goto_3
    or-int/2addr v0, v1

    :cond_5
    and-int/lit16 v1, v12, 0xc00

    if-nez v1, :cond_8

    and-int/lit16 v1, v12, 0x1000

    if-nez v1, :cond_6

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    goto :goto_4

    :cond_6
    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    :goto_4
    if-eqz v1, :cond_7

    const/16 v1, 0x800

    goto :goto_5

    :cond_7
    const/16 v1, 0x400

    :goto_5
    or-int/2addr v0, v1

    :cond_8
    and-int/lit16 v1, v12, 0x6000

    if-nez v1, :cond_a

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_9

    const/16 v1, 0x4000

    goto :goto_6

    :cond_9
    const/16 v1, 0x2000

    :goto_6
    or-int/2addr v0, v1

    :cond_a
    and-int/lit16 v1, v0, 0x2493

    const/16 v4, 0x2492

    const/4 v5, 0x0

    if-eq v1, v4, :cond_b

    const/4 v1, 0x1

    goto :goto_7

    :cond_b
    move v1, v5

    :goto_7
    and-int/lit8 v4, v0, 0x1

    invoke-virtual {v3, v4, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_17

    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    sget-object v4, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/f62;

    sget-object v2, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v16, v2

    check-cast v16, Llyiahf/vczjk/yn4;

    invoke-static {v3}, Llyiahf/vczjk/sb;->OoooO0(Llyiahf/vczjk/rf1;)Landroidx/compose/runtime/OooO00o;

    move-result-object v2

    invoke-static {v11, v3}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v14

    move/from16 v17, v0

    new-array v0, v5, [Ljava/lang/Object;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v15, :cond_c

    new-instance v5, Llyiahf/vczjk/p35;

    const/4 v13, 0x7

    invoke-direct {v5, v13}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v5, Llyiahf/vczjk/le3;

    move-object v13, v2

    move-object v2, v5

    const/4 v5, 0x6

    move-object/from16 v19, v1

    const/4 v1, 0x0

    move-object/from16 v20, v4

    const/16 v4, 0xc00

    move-object v8, v13

    move/from16 v21, v17

    move-object/from16 v13, v19

    move-object/from16 v7, v20

    const/16 v18, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v0

    move-object v1, v3

    check-cast v0, Ljava/util/UUID;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v15, :cond_d

    invoke-static {v1}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v2, Llyiahf/vczjk/xr1;

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_e

    if-ne v4, v15, :cond_f

    :cond_e
    move-object v3, v8

    move-object v8, v0

    goto :goto_8

    :cond_f
    move-object v13, v1

    move-object v0, v4

    move-object/from16 v10, v16

    const/4 v4, 0x1

    goto :goto_9

    :goto_8
    new-instance v0, Llyiahf/vczjk/yj5;

    move-object v4, v10

    move-object v10, v2

    move-object v2, v4

    move-object v11, v3

    move-object v5, v13

    move-wide/from16 v3, p1

    move-object v13, v1

    move-object v1, v6

    move-object/from16 v6, v16

    invoke-direct/range {v0 .. v10}, Llyiahf/vczjk/yj5;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/vk5;JLandroid/view/View;Llyiahf/vczjk/yn4;Llyiahf/vczjk/f62;Ljava/util/UUID;Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;)V

    move-object v10, v6

    new-instance v1, Llyiahf/vczjk/ou;

    const/4 v2, 0x5

    invoke-direct {v1, v14, v2}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    new-instance v2, Llyiahf/vczjk/a91;

    const v3, -0x3eaaaf9b

    const/4 v4, 0x1

    invoke-direct {v2, v3, v1, v4}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    iget-object v1, v0, Llyiahf/vczjk/yj5;->OooOo00:Llyiahf/vczjk/tj5;

    invoke-virtual {v1, v11}, Landroidx/compose/ui/platform/AbstractComposeView;->setParentCompositionContext(Llyiahf/vczjk/lg1;)V

    iget-object v3, v1, Llyiahf/vczjk/tj5;->OooOo0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iput-boolean v4, v1, Llyiahf/vczjk/tj5;->OooOo0O:Z

    invoke-virtual {v1}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0OO()V

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_9
    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/yj5;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_10

    if-ne v1, v15, :cond_11

    :cond_10
    new-instance v1, Llyiahf/vczjk/w45;

    const/4 v0, 0x4

    invoke-direct {v1, v5, v0}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static {v5, v1, v13}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    move/from16 v1, v21

    and-int/lit8 v2, v1, 0xe

    const/4 v3, 0x4

    if-ne v2, v3, :cond_12

    move v2, v4

    goto :goto_a

    :cond_12
    move/from16 v2, v18

    :goto_a
    or-int/2addr v0, v2

    and-int/lit16 v2, v1, 0x380

    const/16 v3, 0x100

    if-ne v2, v3, :cond_13

    move v2, v4

    goto :goto_b

    :cond_13
    move/from16 v2, v18

    :goto_b
    or-int/2addr v0, v2

    and-int/lit8 v1, v1, 0x70

    const/16 v2, 0x20

    if-ne v1, v2, :cond_14

    move v2, v4

    goto :goto_c

    :cond_14
    move/from16 v2, v18

    :goto_c
    or-int/2addr v0, v2

    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_15

    if-ne v1, v15, :cond_16

    :cond_15
    new-instance v4, Llyiahf/vczjk/wk5;

    move-object/from16 v6, p0

    move-wide/from16 v8, p1

    move-object/from16 v7, p3

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/wk5;-><init>(Llyiahf/vczjk/yj5;Llyiahf/vczjk/le3;Llyiahf/vczjk/vk5;JLlyiahf/vczjk/yn4;)V

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v1, v4

    :cond_16
    check-cast v1, Llyiahf/vczjk/le3;

    invoke-static {v1, v13}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    goto :goto_d

    :cond_17
    move-object v13, v3

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_d
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_18

    new-instance v0, Llyiahf/vczjk/xk5;

    move-object/from16 v1, p0

    move-wide/from16 v2, p1

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move v7, v12

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/xk5;-><init>(Llyiahf/vczjk/le3;JLlyiahf/vczjk/vk5;Llyiahf/vczjk/gi;Llyiahf/vczjk/a91;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_18
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JJJJFLlyiahf/vczjk/ab2;Llyiahf/vczjk/rf1;III)V
    .locals 32

    move/from16 v0, p18

    move/from16 v1, p19

    move/from16 v2, p20

    const/4 v5, 0x4

    const/16 v9, 0x80

    const/16 v10, 0x100

    move-object/from16 v11, p17

    check-cast v11, Llyiahf/vczjk/zf1;

    const v12, 0x5a1a0b7

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v12, v0, 0x6

    if-nez v12, :cond_1

    move-object/from16 v12, p0

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_0

    move v14, v5

    goto :goto_0

    :cond_0
    const/4 v14, 0x2

    :goto_0
    or-int/2addr v14, v0

    goto :goto_1

    :cond_1
    move-object/from16 v12, p0

    move v14, v0

    :goto_1
    and-int/lit8 v15, v0, 0x30

    const/16 v16, 0x20

    if-nez v15, :cond_3

    move-object/from16 v15, p1

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v17

    if-eqz v17, :cond_2

    move/from16 v17, v16

    goto :goto_2

    :cond_2
    const/16 v17, 0x10

    :goto_2
    or-int v14, v14, v17

    goto :goto_3

    :cond_3
    move-object/from16 v15, p1

    :goto_3
    and-int/lit8 v17, v2, 0x4

    if-eqz v17, :cond_4

    or-int/lit16 v14, v14, 0x180

    move-object/from16 v4, p2

    const/16 v18, 0x10

    goto :goto_5

    :cond_4
    const/16 v18, 0x10

    and-int/lit16 v4, v0, 0x180

    if-nez v4, :cond_6

    move-object/from16 v4, p2

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_5

    move/from16 v19, v10

    goto :goto_4

    :cond_5
    move/from16 v19, v9

    :goto_4
    or-int v14, v14, v19

    goto :goto_5

    :cond_6
    move-object/from16 v4, p2

    :goto_5
    and-int/lit8 v19, v2, 0x8

    if-eqz v19, :cond_8

    or-int/lit16 v14, v14, 0xc00

    :cond_7
    move-object/from16 v5, p3

    goto :goto_7

    :cond_8
    and-int/lit16 v5, v0, 0xc00

    if-nez v5, :cond_7

    move-object/from16 v5, p3

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_9

    const/16 v21, 0x800

    goto :goto_6

    :cond_9
    const/16 v21, 0x400

    :goto_6
    or-int v14, v14, v21

    :goto_7
    and-int/lit8 v21, v2, 0x10

    const/16 v22, 0x1

    const/4 v6, 0x0

    if-eqz v21, :cond_a

    or-int/lit16 v14, v14, 0x6000

    goto :goto_9

    :cond_a
    and-int/lit16 v13, v0, 0x6000

    if-nez v13, :cond_c

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_b

    const/16 v13, 0x4000

    goto :goto_8

    :cond_b
    const/16 v13, 0x2000

    :goto_8
    or-int/2addr v14, v13

    :cond_c
    :goto_9
    const/high16 v13, 0x30000

    and-int/2addr v13, v0

    if-nez v13, :cond_e

    move-object/from16 v13, p4

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_d

    const/high16 v21, 0x20000

    goto :goto_a

    :cond_d
    const/high16 v21, 0x10000

    :goto_a
    or-int v14, v14, v21

    goto :goto_b

    :cond_e
    move-object/from16 v13, p4

    :goto_b
    const/high16 v21, 0x180000

    and-int v21, v0, v21

    move-object/from16 v6, p5

    if-nez v21, :cond_10

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_f

    const/high16 v23, 0x100000

    goto :goto_c

    :cond_f
    const/high16 v23, 0x80000

    :goto_c
    or-int v14, v14, v23

    :cond_10
    const/high16 v23, 0xc00000

    and-int v23, v0, v23

    if-nez v23, :cond_13

    and-int/lit16 v3, v2, 0x80

    if-nez v3, :cond_11

    move-object/from16 v3, p6

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_12

    const/high16 v24, 0x800000

    goto :goto_d

    :cond_11
    move-object/from16 v3, p6

    :cond_12
    const/high16 v24, 0x400000

    :goto_d
    or-int v14, v14, v24

    goto :goto_e

    :cond_13
    move-object/from16 v3, p6

    :goto_e
    const/high16 v24, 0x6000000

    and-int v24, v0, v24

    if-nez v24, :cond_16

    and-int/lit16 v9, v2, 0x100

    if-nez v9, :cond_14

    move-wide/from16 v8, p7

    invoke-virtual {v11, v8, v9}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v26

    if-eqz v26, :cond_15

    const/high16 v26, 0x4000000

    goto :goto_f

    :cond_14
    move-wide/from16 v8, p7

    :cond_15
    const/high16 v26, 0x2000000

    :goto_f
    or-int v14, v14, v26

    goto :goto_10

    :cond_16
    move-wide/from16 v8, p7

    :goto_10
    const/high16 v26, 0x30000000

    and-int v26, v0, v26

    if-nez v26, :cond_18

    and-int/lit16 v10, v2, 0x200

    move-wide/from16 v7, p9

    if-nez v10, :cond_17

    invoke-virtual {v11, v7, v8}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v9

    if-eqz v9, :cond_17

    const/high16 v9, 0x20000000

    goto :goto_11

    :cond_17
    const/high16 v9, 0x10000000

    :goto_11
    or-int/2addr v14, v9

    goto :goto_12

    :cond_18
    move-wide/from16 v7, p9

    :goto_12
    and-int/lit8 v9, v1, 0x6

    if-nez v9, :cond_1a

    const/16 v10, 0x400

    and-int/lit16 v9, v2, 0x400

    move-wide/from16 v3, p11

    if-nez v9, :cond_19

    invoke-virtual {v11, v3, v4}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v9

    if-eqz v9, :cond_19

    const/16 v20, 0x4

    goto :goto_13

    :cond_19
    const/16 v20, 0x2

    :goto_13
    or-int v9, v1, v20

    goto :goto_14

    :cond_1a
    move-wide/from16 v3, p11

    move v9, v1

    :goto_14
    and-int/lit8 v20, v1, 0x30

    if-nez v20, :cond_1c

    const/16 v10, 0x800

    and-int/lit16 v0, v2, 0x800

    move-wide/from16 v3, p13

    if-nez v0, :cond_1b

    invoke-virtual {v11, v3, v4}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    if-eqz v0, :cond_1b

    goto :goto_15

    :cond_1b
    move/from16 v16, v18

    :goto_15
    or-int v9, v9, v16

    goto :goto_16

    :cond_1c
    move-wide/from16 v3, p13

    :goto_16
    and-int/lit16 v0, v2, 0x1000

    if-eqz v0, :cond_1e

    or-int/lit16 v9, v9, 0x180

    :cond_1d
    move/from16 v10, p15

    :goto_17
    move/from16 v16, v0

    const/16 v0, 0x2000

    goto :goto_19

    :cond_1e
    and-int/lit16 v10, v1, 0x180

    if-nez v10, :cond_1d

    move/from16 v10, p15

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v16

    if-eqz v16, :cond_1f

    const/16 v16, 0x100

    goto :goto_18

    :cond_1f
    const/16 v16, 0x80

    :goto_18
    or-int v9, v9, v16

    goto :goto_17

    :goto_19
    and-int/2addr v0, v2

    if-eqz v0, :cond_21

    or-int/lit16 v9, v9, 0xc00

    move/from16 v18, v0

    :cond_20
    move-object/from16 v0, p16

    goto :goto_1b

    :cond_21
    move/from16 v18, v0

    and-int/lit16 v0, v1, 0xc00

    if-nez v0, :cond_20

    move-object/from16 v0, p16

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_22

    const/16 v20, 0x800

    goto :goto_1a

    :cond_22
    const/16 v20, 0x400

    :goto_1a
    or-int v9, v9, v20

    :goto_1b
    const v20, 0x12492493

    and-int v0, v14, v20

    const v1, 0x12492492

    if-ne v0, v1, :cond_24

    and-int/lit16 v0, v9, 0x493

    const/16 v1, 0x492

    if-eq v0, v1, :cond_23

    goto :goto_1c

    :cond_23
    const/4 v0, 0x0

    goto :goto_1d

    :cond_24
    :goto_1c
    move/from16 v0, v22

    :goto_1d
    and-int/lit8 v1, v14, 0x1

    invoke-virtual {v11, v1, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_35

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, p18, 0x1

    const v1, -0x70000001

    const v20, -0xe000001

    const v22, -0x1c00001

    if-eqz v0, :cond_2b

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_25

    goto :goto_1e

    :cond_25
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    const/16 v0, 0x80

    and-int/2addr v0, v2

    if-eqz v0, :cond_26

    and-int v14, v14, v22

    :cond_26
    const/16 v0, 0x100

    and-int/2addr v0, v2

    if-eqz v0, :cond_27

    and-int v14, v14, v20

    :cond_27
    and-int/lit16 v0, v2, 0x200

    if-eqz v0, :cond_28

    and-int/2addr v14, v1

    :cond_28
    const/16 v10, 0x400

    and-int/lit16 v0, v2, 0x400

    if-eqz v0, :cond_29

    and-int/lit8 v9, v9, -0xf

    :cond_29
    const/16 v10, 0x800

    and-int/lit16 v0, v2, 0x800

    if-eqz v0, :cond_2a

    and-int/lit8 v9, v9, -0x71

    :cond_2a
    move-object/from16 v0, p2

    move-object/from16 v17, p6

    move-wide/from16 v18, p7

    move-wide/from16 v22, p11

    move/from16 v26, p15

    move-object/from16 v27, p16

    move-wide/from16 v24, v3

    move-wide/from16 v20, v7

    move v1, v14

    move-object v14, v5

    goto/16 :goto_29

    :cond_2b
    :goto_1e
    if-eqz v17, :cond_2c

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_1f

    :cond_2c
    move-object/from16 v0, p2

    :goto_1f
    if-eqz v19, :cond_2d

    const/16 v21, 0x0

    :goto_20
    const/16 v5, 0x80

    goto :goto_21

    :cond_2d
    move-object/from16 v21, v5

    goto :goto_20

    :goto_21
    and-int/2addr v5, v2

    if-eqz v5, :cond_2e

    sget v5, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v5, Llyiahf/vczjk/bb2;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v5, v11}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v5

    and-int v14, v14, v22

    :goto_22
    move/from16 p17, v1

    const/16 v1, 0x100

    goto :goto_23

    :cond_2e
    move-object/from16 v5, p6

    goto :goto_22

    :goto_23
    and-int/2addr v1, v2

    if-eqz v1, :cond_2f

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/bb2;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v1, v11}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v22

    and-int v14, v14, v20

    goto :goto_24

    :cond_2f
    move-wide/from16 v22, p7

    :goto_24
    and-int/lit16 v1, v2, 0x200

    if-eqz v1, :cond_30

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/bb2;->OooO:Llyiahf/vczjk/y21;

    invoke-static {v1, v11}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v7

    and-int v1, v14, p17

    move v14, v1

    :cond_30
    const/16 v10, 0x400

    and-int/lit16 v1, v2, 0x400

    if-eqz v1, :cond_31

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/bb2;->OooO0o0:Llyiahf/vczjk/y21;

    invoke-static {v1, v11}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v19

    and-int/lit8 v9, v9, -0xf

    :goto_25
    const/16 v10, 0x800

    goto :goto_26

    :cond_31
    move-wide/from16 v19, p11

    goto :goto_25

    :goto_26
    and-int/lit16 v1, v2, 0x800

    if-eqz v1, :cond_32

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/bb2;->OooO0oO:Llyiahf/vczjk/y21;

    invoke-static {v1, v11}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v3

    and-int/lit8 v1, v9, -0x71

    move v9, v1

    :cond_32
    if-eqz v16, :cond_33

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    goto :goto_27

    :cond_33
    move/from16 v1, p15

    :goto_27
    if-eqz v18, :cond_34

    new-instance v10, Llyiahf/vczjk/ab2;

    move-object/from16 p2, v0

    const/4 v0, 0x7

    invoke-direct {v10, v0}, Llyiahf/vczjk/ab2;-><init>(I)V

    move-wide/from16 v24, v22

    move-wide/from16 v22, v19

    move-wide/from16 v18, v24

    move-object/from16 v0, p2

    move/from16 v26, v1

    move-wide/from16 v24, v3

    move-object/from16 v17, v5

    move-object/from16 v27, v10

    :goto_28
    move v1, v14

    move-object/from16 v14, v21

    move-wide/from16 v20, v7

    goto :goto_29

    :cond_34
    move-object/from16 p2, v0

    move-wide/from16 v24, v22

    move-wide/from16 v22, v19

    move-wide/from16 v18, v24

    move-object/from16 v27, p16

    move/from16 v26, v1

    move-wide/from16 v24, v3

    move-object/from16 v17, v5

    goto :goto_28

    :goto_29
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const v3, 0x7ffffffe

    and-int v29, v1, v3

    and-int/lit16 v1, v9, 0x1ffe

    move/from16 v30, v1

    move-object/from16 v16, v6

    move-object/from16 v28, v11

    move-object v11, v12

    move-object v12, v15

    move-object v15, v13

    move-object v13, v0

    invoke-static/range {v11 .. v30}, Llyiahf/vczjk/j4;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JJJJFLlyiahf/vczjk/ab2;Llyiahf/vczjk/rf1;II)V

    move-object v3, v13

    move-object v4, v14

    move-object/from16 v7, v17

    move-wide/from16 v8, v18

    move-wide/from16 v10, v20

    move-wide/from16 v12, v22

    move-wide/from16 v14, v24

    move/from16 v16, v26

    move-object/from16 v17, v27

    goto :goto_2a

    :cond_35
    move-object/from16 v28, v11

    invoke-virtual/range {v28 .. v28}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v12, p11

    move/from16 v16, p15

    move-object/from16 v17, p16

    move-wide v14, v3

    move-object v4, v5

    move-wide v10, v7

    move-object/from16 v3, p2

    move-object/from16 v7, p6

    move-wide/from16 v8, p7

    :goto_2a
    invoke-virtual/range {v28 .. v28}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_36

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/m9;

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v18, p18

    move/from16 v19, p19

    move-object/from16 v31, v1

    move/from16 v20, v2

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    invoke-direct/range {v0 .. v20}, Llyiahf/vczjk/m9;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JJJJFLlyiahf/vczjk/ab2;III)V

    move-object/from16 v1, v31

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_36
    return-void
.end method

.method public static OooO0O0(F)Llyiahf/vczjk/gi;
    .locals 4

    new-instance v0, Llyiahf/vczjk/gi;

    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    sget-object v1, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    const v2, 0x3c23d70a    # 0.01f

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v3, 0x8

    invoke-direct {v0, p0, v1, v2, v3}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    return-object v0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/bi6;Llyiahf/vczjk/dj1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 11

    move-object v3, p3

    check-cast v3, Llyiahf/vczjk/zf1;

    const p3, 0x8cffb21

    invoke-virtual {v3, p3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 p3, p4, 0x6

    if-nez p3, :cond_1

    invoke-virtual {v3, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p3, p4

    goto :goto_1

    :cond_1
    move p3, p4

    :goto_1
    and-int/lit8 v0, p4, 0x30

    const/16 v1, 0x20

    if-nez v0, :cond_3

    invoke-virtual {v3, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    move v0, v1

    goto :goto_2

    :cond_2
    const/16 v0, 0x10

    :goto_2
    or-int/2addr p3, v0

    :cond_3
    and-int/lit16 v0, p4, 0x180

    const/16 v2, 0x100

    if-nez v0, :cond_5

    invoke-virtual {v3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    move v0, v2

    goto :goto_3

    :cond_4
    const/16 v0, 0x80

    :goto_3
    or-int/2addr p3, v0

    :cond_5
    and-int/lit16 v0, p3, 0x93

    const/16 v4, 0x92

    if-ne v0, v4, :cond_7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_6

    goto :goto_4

    :cond_6
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_7
    :goto_4
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v4, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v4, p0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v7, 0x6

    invoke-static {v5, v6, v3, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v6, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_8

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_a

    :cond_9
    invoke-static {v6, v3, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    new-instance v4, Llyiahf/vczjk/pc;

    const/4 v5, 0x3

    const/4 v6, 0x7

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/pc;-><init>(II)V

    invoke-static {v0, v4}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    const v4, -0x615d173a

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v4, p3, 0x70

    const/4 v6, 0x1

    const/4 v5, 0x0

    if-ne v4, v1, :cond_b

    move v7, v6

    goto :goto_6

    :cond_b
    move v7, v5

    :goto_6
    and-int/lit16 p3, p3, 0x380

    if-ne p3, v2, :cond_c

    move p3, v6

    goto :goto_7

    :cond_c
    move p3, v5

    :goto_7
    or-int/2addr p3, v7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p3, :cond_d

    if-ne v2, v7, :cond_e

    :cond_d
    new-instance v2, Llyiahf/vczjk/o0OO000o;

    const/16 p3, 0xc

    invoke-direct {v2, p3, p1, p2}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const p3, 0x4c5de2

    invoke-virtual {v3, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-ne v4, v1, :cond_f

    move p3, v6

    goto :goto_8

    :cond_f
    move p3, v5

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p3, :cond_10

    if-ne v1, v7, :cond_11

    :cond_10
    new-instance v1, Llyiahf/vczjk/o000OO;

    const/16 p3, 0x13

    invoke-direct {v1, p1, p3}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v10, v1

    move-object v1, v0

    move-object v0, v2

    move-object v2, v10

    invoke-static/range {v0 .. v5}, Landroidx/compose/ui/viewinterop/OooO00o;->OooO00o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p3

    if-eqz p3, :cond_12

    new-instance v0, Llyiahf/vczjk/z4;

    const/4 v5, 0x1

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/z4;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, p3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move/from16 v10, p10

    move/from16 v11, p11

    move-object/from16 v0, p9

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x2c266969

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, v11, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v2, v10, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v10, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v10

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v10

    :goto_1
    and-int/lit8 v4, v10, 0x30

    if-nez v4, :cond_5

    and-int/lit8 v4, v11, 0x2

    if-nez v4, :cond_3

    move-object/from16 v4, p1

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x20

    goto :goto_2

    :cond_3
    move-object/from16 v4, p1

    :cond_4
    const/16 v5, 0x10

    :goto_2
    or-int/2addr v3, v5

    goto :goto_3

    :cond_5
    move-object/from16 v4, p1

    :goto_3
    and-int/lit8 v5, v11, 0x4

    if-eqz v5, :cond_7

    or-int/lit16 v3, v3, 0x180

    :cond_6
    move-object/from16 v6, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v6, v10, 0x180

    if-nez v6, :cond_6

    move-object/from16 v6, p2

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/16 v7, 0x100

    goto :goto_4

    :cond_8
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v3, v7

    :goto_5
    and-int/lit8 v7, v11, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v3, v3, 0xc00

    :cond_9
    move/from16 v8, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v8, v10, 0xc00

    if-nez v8, :cond_9

    move/from16 v8, p3

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    if-eqz v9, :cond_b

    const/16 v9, 0x800

    goto :goto_6

    :cond_b
    const/16 v9, 0x400

    :goto_6
    or-int/2addr v3, v9

    :goto_7
    and-int/lit16 v9, v10, 0x6000

    if-nez v9, :cond_e

    and-int/lit8 v9, v11, 0x10

    if-nez v9, :cond_c

    move-object/from16 v9, p4

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_d

    const/16 v12, 0x4000

    goto :goto_8

    :cond_c
    move-object/from16 v9, p4

    :cond_d
    const/16 v12, 0x2000

    :goto_8
    or-int/2addr v3, v12

    goto :goto_9

    :cond_e
    move-object/from16 v9, p4

    :goto_9
    and-int/lit8 v12, v11, 0x20

    const/high16 v13, 0x30000

    if-eqz v12, :cond_10

    or-int/2addr v3, v13

    :cond_f
    move-object/from16 v13, p5

    goto :goto_b

    :cond_10
    and-int/2addr v13, v10

    if-nez v13, :cond_f

    move-object/from16 v13, p5

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    const/high16 v14, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v14, 0x10000

    :goto_a
    or-int/2addr v3, v14

    :goto_b
    const/high16 v14, 0x180000

    and-int/2addr v14, v10

    if-nez v14, :cond_14

    and-int/lit8 v14, v11, 0x40

    if-nez v14, :cond_12

    move-object/from16 v14, p6

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_13

    const/high16 v15, 0x100000

    goto :goto_c

    :cond_12
    move-object/from16 v14, p6

    :cond_13
    const/high16 v15, 0x80000

    :goto_c
    or-int/2addr v3, v15

    goto :goto_d

    :cond_14
    move-object/from16 v14, p6

    :goto_d
    and-int/lit16 v15, v11, 0x80

    const/high16 v16, 0xc00000

    if-eqz v15, :cond_15

    or-int v3, v3, v16

    move/from16 p9, v1

    move/from16 v1, p7

    goto :goto_f

    :cond_15
    and-int v16, v10, v16

    move/from16 p9, v1

    move/from16 v1, p7

    if-nez v16, :cond_17

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v16

    if-eqz v16, :cond_16

    const/high16 v16, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v16, 0x400000

    :goto_e
    or-int v3, v3, v16

    :cond_17
    :goto_f
    and-int/lit16 v1, v11, 0x100

    const/high16 v16, 0x6000000

    if-eqz v1, :cond_19

    or-int v3, v3, v16

    :cond_18
    move-object/from16 v1, p8

    goto :goto_11

    :cond_19
    and-int v1, v10, v16

    if-nez v1, :cond_18

    move-object/from16 v1, p8

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1a

    const/high16 v16, 0x4000000

    goto :goto_10

    :cond_1a
    const/high16 v16, 0x2000000

    :goto_10
    or-int v3, v3, v16

    :goto_11
    const v16, 0x2492493

    and-int v1, v3, v16

    const/16 v16, 0x1

    const v2, 0x2492492

    move/from16 v17, v3

    const/4 v3, 0x0

    if-eq v1, v2, :cond_1b

    move/from16 v1, v16

    goto :goto_12

    :cond_1b
    move v1, v3

    :goto_12
    and-int/lit8 v2, v17, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_2c

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v10, 0x1

    const/4 v2, 0x3

    const v18, -0x380001

    const v19, -0xe001

    if-eqz v1, :cond_20

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_1c

    goto :goto_15

    :cond_1c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v1, v11, 0x2

    if-eqz v1, :cond_1d

    and-int/lit8 v3, v17, -0x71

    goto :goto_13

    :cond_1d
    move/from16 v3, v17

    :goto_13
    and-int/lit8 v1, v11, 0x10

    if-eqz v1, :cond_1e

    and-int v3, v3, v19

    :cond_1e
    and-int/lit8 v1, v11, 0x40

    if-eqz v1, :cond_1f

    and-int v3, v3, v18

    :cond_1f
    move-object/from16 v12, p0

    move/from16 v19, p7

    :goto_14
    move v15, v8

    move-object/from16 v16, v9

    move-object/from16 v17, v13

    move-object/from16 v18, v14

    move-object v13, v4

    move-object v14, v6

    goto/16 :goto_19

    :cond_20
    :goto_15
    if-eqz p9, :cond_21

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_16

    :cond_21
    move-object/from16 v1, p0

    :goto_16
    and-int/lit8 v20, v11, 0x2

    if-eqz v20, :cond_22

    invoke-static {v3, v2, v0}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v4

    and-int/lit8 v17, v17, -0x71

    :cond_22
    if-eqz v5, :cond_23

    int-to-float v5, v3

    new-instance v6, Llyiahf/vczjk/di6;

    invoke-direct {v6, v5, v5, v5, v5}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    :cond_23
    if-eqz v7, :cond_24

    move v8, v3

    :cond_24
    and-int/lit8 v3, v11, 0x10

    if-eqz v3, :cond_26

    if-nez v8, :cond_25

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    goto :goto_17

    :cond_25
    sget-object v3, Llyiahf/vczjk/tx;->OooO0Oo:Llyiahf/vczjk/wp3;

    :goto_17
    and-int v17, v17, v19

    move-object v9, v3

    :cond_26
    if-eqz v12, :cond_27

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    move-object v13, v3

    :cond_27
    and-int/lit8 v3, v11, 0x40

    if-eqz v3, :cond_2a

    invoke-static {v0}, Llyiahf/vczjk/xy8;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_28

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v5, :cond_29

    :cond_28
    new-instance v7, Llyiahf/vczjk/f22;

    invoke-direct {v7, v3}, Llyiahf/vczjk/f22;-><init>(Llyiahf/vczjk/t02;)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_29
    move-object v3, v7

    check-cast v3, Llyiahf/vczjk/f22;

    and-int v5, v17, v18

    move-object v14, v3

    move v3, v5

    goto :goto_18

    :cond_2a
    move/from16 v3, v17

    :goto_18
    if-eqz v15, :cond_2b

    move-object v12, v1

    move v15, v8

    move-object/from16 v17, v13

    move-object/from16 v18, v14

    move/from16 v19, v16

    move-object v13, v4

    move-object v14, v6

    move-object/from16 v16, v9

    goto :goto_19

    :cond_2b
    move/from16 v19, p7

    move-object v12, v1

    goto :goto_14

    :goto_19
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-static {v0}, Llyiahf/vczjk/rg6;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;

    move-result-object v20

    const v1, 0x1fffffe

    and-int/2addr v1, v3

    const/high16 v4, 0x70000000

    shl-int/lit8 v2, v3, 0x3

    and-int/2addr v2, v4

    or-int v23, v1, v2

    const/16 v24, 0x0

    move-object/from16 v21, p8

    move-object/from16 v22, v0

    invoke-static/range {v12 .. v24}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object v1, v12

    move-object v2, v13

    move-object v3, v14

    move v4, v15

    move-object/from16 v5, v16

    move-object/from16 v6, v17

    move-object/from16 v7, v18

    move/from16 v8, v19

    goto :goto_1a

    :cond_2c
    move-object/from16 v22, v0

    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object v2, v4

    move-object v3, v6

    move v4, v8

    move-object v5, v9

    move-object v6, v13

    move-object v7, v14

    move/from16 v8, p7

    :goto_1a
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v12

    if-eqz v12, :cond_2d

    new-instance v0, Llyiahf/vczjk/op4;

    move-object/from16 v9, p8

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/op4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v12, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2d
    return-void
.end method

.method public static final OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move/from16 v10, p10

    move/from16 v11, p11

    move-object/from16 v0, p9

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x66c6b0c5

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, v11, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v2, v10, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v10, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v10

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v10

    :goto_1
    and-int/lit8 v4, v10, 0x30

    if-nez v4, :cond_5

    and-int/lit8 v4, v11, 0x2

    if-nez v4, :cond_3

    move-object/from16 v4, p1

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x20

    goto :goto_2

    :cond_3
    move-object/from16 v4, p1

    :cond_4
    const/16 v5, 0x10

    :goto_2
    or-int/2addr v3, v5

    goto :goto_3

    :cond_5
    move-object/from16 v4, p1

    :goto_3
    and-int/lit8 v5, v11, 0x4

    if-eqz v5, :cond_7

    or-int/lit16 v3, v3, 0x180

    :cond_6
    move-object/from16 v6, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v6, v10, 0x180

    if-nez v6, :cond_6

    move-object/from16 v6, p2

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/16 v7, 0x100

    goto :goto_4

    :cond_8
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v3, v7

    :goto_5
    and-int/lit8 v7, v11, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v3, v3, 0xc00

    :cond_9
    move/from16 v8, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v8, v10, 0xc00

    if-nez v8, :cond_9

    move/from16 v8, p3

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    if-eqz v9, :cond_b

    const/16 v9, 0x800

    goto :goto_6

    :cond_b
    const/16 v9, 0x400

    :goto_6
    or-int/2addr v3, v9

    :goto_7
    and-int/lit16 v9, v10, 0x6000

    if-nez v9, :cond_e

    and-int/lit8 v9, v11, 0x10

    if-nez v9, :cond_c

    move-object/from16 v9, p4

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_d

    const/16 v12, 0x4000

    goto :goto_8

    :cond_c
    move-object/from16 v9, p4

    :cond_d
    const/16 v12, 0x2000

    :goto_8
    or-int/2addr v3, v12

    goto :goto_9

    :cond_e
    move-object/from16 v9, p4

    :goto_9
    and-int/lit8 v12, v11, 0x20

    const/high16 v13, 0x30000

    if-eqz v12, :cond_10

    or-int/2addr v3, v13

    :cond_f
    move-object/from16 v13, p5

    goto :goto_b

    :cond_10
    and-int/2addr v13, v10

    if-nez v13, :cond_f

    move-object/from16 v13, p5

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    const/high16 v14, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v14, 0x10000

    :goto_a
    or-int/2addr v3, v14

    :goto_b
    const/high16 v14, 0x180000

    and-int/2addr v14, v10

    if-nez v14, :cond_14

    and-int/lit8 v14, v11, 0x40

    if-nez v14, :cond_12

    move-object/from16 v14, p6

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_13

    const/high16 v15, 0x100000

    goto :goto_c

    :cond_12
    move-object/from16 v14, p6

    :cond_13
    const/high16 v15, 0x80000

    :goto_c
    or-int/2addr v3, v15

    goto :goto_d

    :cond_14
    move-object/from16 v14, p6

    :goto_d
    and-int/lit16 v15, v11, 0x80

    const/high16 v16, 0xc00000

    if-eqz v15, :cond_15

    or-int v3, v3, v16

    move/from16 p9, v1

    move/from16 v1, p7

    goto :goto_f

    :cond_15
    and-int v16, v10, v16

    move/from16 p9, v1

    move/from16 v1, p7

    if-nez v16, :cond_17

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v16

    if-eqz v16, :cond_16

    const/high16 v16, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v16, 0x400000

    :goto_e
    or-int v3, v3, v16

    :cond_17
    :goto_f
    and-int/lit16 v1, v11, 0x100

    const/high16 v16, 0x6000000

    if-eqz v1, :cond_19

    or-int v3, v3, v16

    :cond_18
    move-object/from16 v1, p8

    goto :goto_11

    :cond_19
    and-int v1, v10, v16

    if-nez v1, :cond_18

    move-object/from16 v1, p8

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1a

    const/high16 v16, 0x4000000

    goto :goto_10

    :cond_1a
    const/high16 v16, 0x2000000

    :goto_10
    or-int v3, v3, v16

    :goto_11
    const v16, 0x2492493

    and-int v1, v3, v16

    const/16 v16, 0x1

    const v2, 0x2492492

    move/from16 v17, v3

    const/4 v3, 0x0

    if-eq v1, v2, :cond_1b

    move/from16 v1, v16

    goto :goto_12

    :cond_1b
    move v1, v3

    :goto_12
    and-int/lit8 v2, v17, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_2c

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v10, 0x1

    const/4 v2, 0x3

    const v18, -0x380001

    const v19, -0xe001

    if-eqz v1, :cond_20

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_1c

    goto :goto_15

    :cond_1c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v1, v11, 0x2

    if-eqz v1, :cond_1d

    and-int/lit8 v3, v17, -0x71

    goto :goto_13

    :cond_1d
    move/from16 v3, v17

    :goto_13
    and-int/lit8 v1, v11, 0x10

    if-eqz v1, :cond_1e

    and-int v3, v3, v19

    :cond_1e
    and-int/lit8 v1, v11, 0x40

    if-eqz v1, :cond_1f

    and-int v3, v3, v18

    :cond_1f
    move-object/from16 v12, p0

    move/from16 v19, p7

    :goto_14
    move v15, v8

    move-object/from16 v16, v9

    move-object/from16 v17, v13

    move-object/from16 v18, v14

    move-object v13, v4

    move-object v14, v6

    goto/16 :goto_19

    :cond_20
    :goto_15
    if-eqz p9, :cond_21

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_16

    :cond_21
    move-object/from16 v1, p0

    :goto_16
    and-int/lit8 v20, v11, 0x2

    if-eqz v20, :cond_22

    invoke-static {v3, v2, v0}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v4

    and-int/lit8 v17, v17, -0x71

    :cond_22
    if-eqz v5, :cond_23

    int-to-float v5, v3

    new-instance v6, Llyiahf/vczjk/di6;

    invoke-direct {v6, v5, v5, v5, v5}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    :cond_23
    if-eqz v7, :cond_24

    move v8, v3

    :cond_24
    and-int/lit8 v3, v11, 0x10

    if-eqz v3, :cond_26

    if-nez v8, :cond_25

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    goto :goto_17

    :cond_25
    sget-object v3, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    :goto_17
    and-int v17, v17, v19

    move-object v9, v3

    :cond_26
    if-eqz v12, :cond_27

    sget-object v3, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    move-object v13, v3

    :cond_27
    and-int/lit8 v3, v11, 0x40

    if-eqz v3, :cond_2a

    invoke-static {v0}, Llyiahf/vczjk/xy8;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_28

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v5, :cond_29

    :cond_28
    new-instance v7, Llyiahf/vczjk/f22;

    invoke-direct {v7, v3}, Llyiahf/vczjk/f22;-><init>(Llyiahf/vczjk/t02;)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_29
    move-object v3, v7

    check-cast v3, Llyiahf/vczjk/f22;

    and-int v5, v17, v18

    move-object v14, v3

    move v3, v5

    goto :goto_18

    :cond_2a
    move/from16 v3, v17

    :goto_18
    if-eqz v15, :cond_2b

    move-object v12, v1

    move v15, v8

    move-object/from16 v17, v13

    move-object/from16 v18, v14

    move/from16 v19, v16

    move-object v13, v4

    move-object v14, v6

    move-object/from16 v16, v9

    goto :goto_19

    :cond_2b
    move/from16 v19, p7

    move-object v12, v1

    goto :goto_14

    :goto_19
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-static {v0}, Llyiahf/vczjk/rg6;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;

    move-result-object v20

    const v1, 0x1fffffe

    and-int/2addr v1, v3

    const/high16 v4, 0x70000000

    shl-int/lit8 v2, v3, 0x3

    and-int/2addr v2, v4

    or-int v23, v1, v2

    const/16 v24, 0x0

    move-object/from16 v21, p8

    move-object/from16 v22, v0

    invoke-static/range {v12 .. v24}, Llyiahf/vczjk/mc4;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object v1, v12

    move-object v2, v13

    move-object v3, v14

    move v4, v15

    move-object/from16 v5, v16

    move-object/from16 v6, v17

    move-object/from16 v7, v18

    move/from16 v8, v19

    goto :goto_1a

    :cond_2c
    move-object/from16 v22, v0

    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object v2, v4

    move-object v3, v6

    move v4, v8

    move-object v5, v9

    move-object v6, v13

    move-object v7, v14

    move/from16 v8, p7

    :goto_1a
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v12

    if-eqz v12, :cond_2d

    new-instance v0, Llyiahf/vczjk/qp4;

    move-object/from16 v9, p8

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/qp4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v12, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2d
    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 31

    move/from16 v11, p11

    move/from16 v12, p12

    move-object/from16 v0, p10

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, 0x3335543

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, v12, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v2, v11, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v11, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v11

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v11

    :goto_1
    and-int/lit8 v4, v11, 0x30

    if-nez v4, :cond_5

    and-int/lit8 v4, v12, 0x2

    if-nez v4, :cond_3

    move-object/from16 v4, p1

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x20

    goto :goto_2

    :cond_3
    move-object/from16 v4, p1

    :cond_4
    const/16 v5, 0x10

    :goto_2
    or-int/2addr v3, v5

    goto :goto_3

    :cond_5
    move-object/from16 v4, p1

    :goto_3
    and-int/lit8 v5, v12, 0x4

    if-eqz v5, :cond_7

    or-int/lit16 v3, v3, 0x180

    :cond_6
    move-object/from16 v6, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v6, v11, 0x180

    if-nez v6, :cond_6

    move-object/from16 v6, p2

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/16 v7, 0x100

    goto :goto_4

    :cond_8
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v3, v7

    :goto_5
    and-int/lit8 v7, v12, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v3, v3, 0xc00

    :cond_9
    move/from16 v8, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v8, v11, 0xc00

    if-nez v8, :cond_9

    move/from16 v8, p3

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    if-eqz v9, :cond_b

    const/16 v9, 0x800

    goto :goto_6

    :cond_b
    const/16 v9, 0x400

    :goto_6
    or-int/2addr v3, v9

    :goto_7
    and-int/lit16 v9, v11, 0x6000

    if-nez v9, :cond_e

    and-int/lit8 v9, v12, 0x10

    if-nez v9, :cond_c

    move-object/from16 v9, p4

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_d

    const/16 v10, 0x4000

    goto :goto_8

    :cond_c
    move-object/from16 v9, p4

    :cond_d
    const/16 v10, 0x2000

    :goto_8
    or-int/2addr v3, v10

    goto :goto_9

    :cond_e
    move-object/from16 v9, p4

    :goto_9
    and-int/lit8 v10, v12, 0x20

    const/high16 v13, 0x30000

    if-eqz v10, :cond_10

    or-int/2addr v3, v13

    :cond_f
    move-object/from16 v13, p5

    goto :goto_b

    :cond_10
    and-int/2addr v13, v11

    if-nez v13, :cond_f

    move-object/from16 v13, p5

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    const/high16 v14, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v14, 0x10000

    :goto_a
    or-int/2addr v3, v14

    :goto_b
    const/high16 v14, 0x180000

    and-int/2addr v14, v11

    if-nez v14, :cond_14

    and-int/lit8 v14, v12, 0x40

    if-nez v14, :cond_12

    move-object/from16 v14, p6

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_13

    const/high16 v15, 0x100000

    goto :goto_c

    :cond_12
    move-object/from16 v14, p6

    :cond_13
    const/high16 v15, 0x80000

    :goto_c
    or-int/2addr v3, v15

    goto :goto_d

    :cond_14
    move-object/from16 v14, p6

    :goto_d
    and-int/lit16 v15, v12, 0x80

    const/high16 v16, 0xc00000

    if-eqz v15, :cond_15

    or-int v3, v3, v16

    move/from16 p10, v1

    move/from16 v1, p7

    goto :goto_f

    :cond_15
    and-int v16, v11, v16

    move/from16 p10, v1

    move/from16 v1, p7

    if-nez v16, :cond_17

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v16

    if-eqz v16, :cond_16

    const/high16 v16, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v16, 0x400000

    :goto_e
    or-int v3, v3, v16

    :cond_17
    :goto_f
    const/high16 v16, 0x6000000

    and-int v16, v11, v16

    if-nez v16, :cond_1a

    and-int/lit16 v1, v12, 0x100

    if-nez v1, :cond_18

    move-object/from16 v1, p8

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_19

    const/high16 v16, 0x4000000

    goto :goto_10

    :cond_18
    move-object/from16 v1, p8

    :cond_19
    const/high16 v16, 0x2000000

    :goto_10
    or-int v3, v3, v16

    goto :goto_11

    :cond_1a
    move-object/from16 v1, p8

    :goto_11
    and-int/lit16 v1, v12, 0x200

    const/high16 v16, 0x30000000

    if-eqz v1, :cond_1c

    or-int v3, v3, v16

    :cond_1b
    move-object/from16 v1, p9

    goto :goto_13

    :cond_1c
    and-int v1, v11, v16

    if-nez v1, :cond_1b

    move-object/from16 v1, p9

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1d

    const/high16 v16, 0x20000000

    goto :goto_12

    :cond_1d
    const/high16 v16, 0x10000000

    :goto_12
    or-int v3, v3, v16

    :goto_13
    const v16, 0x12492493

    and-int v1, v3, v16

    const/16 v16, 0x1

    const v2, 0x12492492

    move/from16 v17, v3

    const/4 v3, 0x0

    if-eq v1, v2, :cond_1e

    move/from16 v1, v16

    goto :goto_14

    :cond_1e
    move v1, v3

    :goto_14
    and-int/lit8 v2, v17, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_31

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v11, 0x1

    const v2, -0xe000001

    const v18, -0x380001

    const v19, -0xe001

    if-eqz v1, :cond_24

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_1f

    goto :goto_16

    :cond_1f
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v1, v12, 0x2

    if-eqz v1, :cond_20

    and-int/lit8 v3, v17, -0x71

    goto :goto_15

    :cond_20
    move/from16 v3, v17

    :goto_15
    and-int/lit8 v1, v12, 0x10

    if-eqz v1, :cond_21

    and-int v3, v3, v19

    :cond_21
    and-int/lit8 v1, v12, 0x40

    if-eqz v1, :cond_22

    and-int v3, v3, v18

    :cond_22
    and-int/lit16 v1, v12, 0x100

    if-eqz v1, :cond_23

    and-int/2addr v3, v2

    :cond_23
    move/from16 v19, p7

    move-object/from16 v20, p8

    move-object v15, v6

    move/from16 v16, v8

    move-object/from16 v23, v9

    move-object/from16 v22, v13

    move-object/from16 v18, v14

    move-object/from16 v13, p0

    move-object v14, v4

    goto/16 :goto_1e

    :cond_24
    :goto_16
    if-eqz p10, :cond_25

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_17

    :cond_25
    move-object/from16 v1, p0

    :goto_17
    and-int/lit8 v20, v12, 0x2

    if-eqz v20, :cond_26

    const/4 v4, 0x3

    invoke-static {v3, v4, v0}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v4

    and-int/lit8 v17, v17, -0x71

    :cond_26
    if-eqz v5, :cond_27

    int-to-float v5, v3

    new-instance v6, Llyiahf/vczjk/di6;

    invoke-direct {v6, v5, v5, v5, v5}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    :cond_27
    if-eqz v7, :cond_28

    goto :goto_18

    :cond_28
    move v3, v8

    :goto_18
    and-int/lit8 v5, v12, 0x10

    if-eqz v5, :cond_2a

    if-nez v3, :cond_29

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    goto :goto_19

    :cond_29
    sget-object v5, Llyiahf/vczjk/tx;->OooO0Oo:Llyiahf/vczjk/wp3;

    :goto_19
    and-int v17, v17, v19

    goto :goto_1a

    :cond_2a
    move-object v5, v9

    :goto_1a
    if-eqz v10, :cond_2b

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    goto :goto_1b

    :cond_2b
    move-object v7, v13

    :goto_1b
    and-int/lit8 v8, v12, 0x40

    if-eqz v8, :cond_2e

    invoke-static {v0}, Llyiahf/vczjk/xy8;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;

    move-result-object v8

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_2c

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v10, v9, :cond_2d

    :cond_2c
    new-instance v10, Llyiahf/vczjk/f22;

    invoke-direct {v10, v8}, Llyiahf/vczjk/f22;-><init>(Llyiahf/vczjk/t02;)V

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2d
    move-object v8, v10

    check-cast v8, Llyiahf/vczjk/f22;

    and-int v9, v17, v18

    goto :goto_1c

    :cond_2e
    move-object v8, v14

    move/from16 v9, v17

    :goto_1c
    if-eqz v15, :cond_2f

    goto :goto_1d

    :cond_2f
    move/from16 v16, p7

    :goto_1d
    and-int/lit16 v10, v12, 0x100

    if-eqz v10, :cond_30

    invoke-static {v0}, Llyiahf/vczjk/rg6;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;

    move-result-object v10

    and-int/2addr v2, v9

    move-object v13, v1

    move-object v14, v4

    move-object/from16 v23, v5

    move-object v15, v6

    move-object/from16 v22, v7

    move-object/from16 v18, v8

    move-object/from16 v20, v10

    move/from16 v19, v16

    move/from16 v16, v3

    move v3, v2

    goto :goto_1e

    :cond_30
    move-object/from16 v20, p8

    move-object v13, v1

    move-object v14, v4

    move-object/from16 v23, v5

    move-object v15, v6

    move-object/from16 v22, v7

    move-object/from16 v18, v8

    move/from16 v19, v16

    move/from16 v16, v3

    move v3, v9

    :goto_1e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    and-int/lit8 v1, v3, 0xe

    or-int/lit16 v1, v1, 0x6000

    and-int/lit8 v2, v3, 0x70

    or-int/2addr v1, v2

    and-int/lit16 v2, v3, 0x380

    or-int/2addr v1, v2

    and-int/lit16 v2, v3, 0x1c00

    or-int/2addr v1, v2

    shr-int/lit8 v2, v3, 0x3

    const/high16 v4, 0x70000

    and-int/2addr v4, v2

    or-int/2addr v1, v4

    const/high16 v4, 0x380000

    and-int/2addr v4, v2

    or-int/2addr v1, v4

    const/high16 v4, 0x1c00000

    and-int/2addr v2, v4

    or-int/2addr v1, v2

    shl-int/lit8 v2, v3, 0xc

    const/high16 v4, 0x70000000

    and-int/2addr v2, v4

    or-int v28, v1, v2

    shr-int/lit8 v1, v3, 0xc

    and-int/lit8 v1, v1, 0xe

    shr-int/lit8 v2, v3, 0x12

    and-int/lit16 v2, v2, 0x1c00

    or-int v29, v1, v2

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v17, 0x1

    const/16 v21, 0x0

    const/16 v30, 0x1900

    move-object/from16 v26, p9

    move-object/from16 v27, v0

    invoke-static/range {v13 .. v30}, Llyiahf/vczjk/bua;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZZLlyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;ILlyiahf/vczjk/m4;Llyiahf/vczjk/px;Llyiahf/vczjk/n4;Llyiahf/vczjk/nx;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    move-object v1, v13

    move-object v2, v14

    move-object v3, v15

    move/from16 v4, v16

    move-object/from16 v7, v18

    move/from16 v8, v19

    move-object/from16 v9, v20

    move-object/from16 v6, v22

    move-object/from16 v5, v23

    goto :goto_1f

    :cond_31
    move-object/from16 v27, v0

    invoke-virtual/range {v27 .. v27}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object v2, v4

    move-object v3, v6

    move v4, v8

    move-object v5, v9

    move-object v6, v13

    move-object v7, v14

    move/from16 v8, p7

    move-object/from16 v9, p8

    :goto_1f
    invoke-virtual/range {v27 .. v27}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v13

    if-eqz v13, :cond_32

    new-instance v0, Llyiahf/vczjk/np4;

    move-object/from16 v10, p9

    invoke-direct/range {v0 .. v12}, Llyiahf/vczjk/np4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v13, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_32
    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 31

    move/from16 v11, p11

    move/from16 v12, p12

    move-object/from16 v0, p10

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x705086e1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, v12, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v2, v11, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v11, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v11

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v11

    :goto_1
    and-int/lit8 v4, v11, 0x30

    if-nez v4, :cond_5

    and-int/lit8 v4, v12, 0x2

    if-nez v4, :cond_3

    move-object/from16 v4, p1

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x20

    goto :goto_2

    :cond_3
    move-object/from16 v4, p1

    :cond_4
    const/16 v5, 0x10

    :goto_2
    or-int/2addr v3, v5

    goto :goto_3

    :cond_5
    move-object/from16 v4, p1

    :goto_3
    and-int/lit8 v5, v12, 0x4

    if-eqz v5, :cond_7

    or-int/lit16 v3, v3, 0x180

    :cond_6
    move-object/from16 v6, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v6, v11, 0x180

    if-nez v6, :cond_6

    move-object/from16 v6, p2

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/16 v7, 0x100

    goto :goto_4

    :cond_8
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v3, v7

    :goto_5
    and-int/lit8 v7, v12, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v3, v3, 0xc00

    :cond_9
    move/from16 v8, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v8, v11, 0xc00

    if-nez v8, :cond_9

    move/from16 v8, p3

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    if-eqz v9, :cond_b

    const/16 v9, 0x800

    goto :goto_6

    :cond_b
    const/16 v9, 0x400

    :goto_6
    or-int/2addr v3, v9

    :goto_7
    and-int/lit16 v9, v11, 0x6000

    if-nez v9, :cond_e

    and-int/lit8 v9, v12, 0x10

    if-nez v9, :cond_c

    move-object/from16 v9, p4

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_d

    const/16 v10, 0x4000

    goto :goto_8

    :cond_c
    move-object/from16 v9, p4

    :cond_d
    const/16 v10, 0x2000

    :goto_8
    or-int/2addr v3, v10

    goto :goto_9

    :cond_e
    move-object/from16 v9, p4

    :goto_9
    and-int/lit8 v10, v12, 0x20

    const/high16 v13, 0x30000

    if-eqz v10, :cond_10

    or-int/2addr v3, v13

    :cond_f
    move-object/from16 v13, p5

    goto :goto_b

    :cond_10
    and-int/2addr v13, v11

    if-nez v13, :cond_f

    move-object/from16 v13, p5

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    const/high16 v14, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v14, 0x10000

    :goto_a
    or-int/2addr v3, v14

    :goto_b
    const/high16 v14, 0x180000

    and-int/2addr v14, v11

    if-nez v14, :cond_14

    and-int/lit8 v14, v12, 0x40

    if-nez v14, :cond_12

    move-object/from16 v14, p6

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_13

    const/high16 v15, 0x100000

    goto :goto_c

    :cond_12
    move-object/from16 v14, p6

    :cond_13
    const/high16 v15, 0x80000

    :goto_c
    or-int/2addr v3, v15

    goto :goto_d

    :cond_14
    move-object/from16 v14, p6

    :goto_d
    and-int/lit16 v15, v12, 0x80

    const/high16 v16, 0xc00000

    if-eqz v15, :cond_15

    or-int v3, v3, v16

    move/from16 p10, v1

    move/from16 v1, p7

    goto :goto_f

    :cond_15
    and-int v16, v11, v16

    move/from16 p10, v1

    move/from16 v1, p7

    if-nez v16, :cond_17

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v16

    if-eqz v16, :cond_16

    const/high16 v16, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v16, 0x400000

    :goto_e
    or-int v3, v3, v16

    :cond_17
    :goto_f
    const/high16 v16, 0x6000000

    and-int v16, v11, v16

    if-nez v16, :cond_1a

    and-int/lit16 v1, v12, 0x100

    if-nez v1, :cond_18

    move-object/from16 v1, p8

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_19

    const/high16 v16, 0x4000000

    goto :goto_10

    :cond_18
    move-object/from16 v1, p8

    :cond_19
    const/high16 v16, 0x2000000

    :goto_10
    or-int v3, v3, v16

    goto :goto_11

    :cond_1a
    move-object/from16 v1, p8

    :goto_11
    and-int/lit16 v1, v12, 0x200

    const/high16 v16, 0x30000000

    if-eqz v1, :cond_1c

    or-int v3, v3, v16

    :cond_1b
    move-object/from16 v1, p9

    goto :goto_13

    :cond_1c
    and-int v1, v11, v16

    if-nez v1, :cond_1b

    move-object/from16 v1, p9

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_1d

    const/high16 v16, 0x20000000

    goto :goto_12

    :cond_1d
    const/high16 v16, 0x10000000

    :goto_12
    or-int v3, v3, v16

    :goto_13
    const v16, 0x12492493

    and-int v1, v3, v16

    const/16 v16, 0x1

    const v2, 0x12492492

    move/from16 v17, v3

    const/4 v3, 0x0

    if-eq v1, v2, :cond_1e

    move/from16 v1, v16

    goto :goto_14

    :cond_1e
    move v1, v3

    :goto_14
    and-int/lit8 v2, v17, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_31

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v11, 0x1

    const v2, -0xe000001

    const v18, -0x380001

    const v19, -0xe001

    if-eqz v1, :cond_24

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_1f

    goto :goto_16

    :cond_1f
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v1, v12, 0x2

    if-eqz v1, :cond_20

    and-int/lit8 v3, v17, -0x71

    goto :goto_15

    :cond_20
    move/from16 v3, v17

    :goto_15
    and-int/lit8 v1, v12, 0x10

    if-eqz v1, :cond_21

    and-int v3, v3, v19

    :cond_21
    and-int/lit8 v1, v12, 0x40

    if-eqz v1, :cond_22

    and-int v3, v3, v18

    :cond_22
    and-int/lit16 v1, v12, 0x100

    if-eqz v1, :cond_23

    and-int/2addr v3, v2

    :cond_23
    move/from16 v19, p7

    move-object/from16 v20, p8

    move-object v15, v6

    move/from16 v16, v8

    move-object/from16 v25, v9

    move-object/from16 v24, v13

    move-object/from16 v18, v14

    move-object/from16 v13, p0

    move-object v14, v4

    goto/16 :goto_1e

    :cond_24
    :goto_16
    if-eqz p10, :cond_25

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_17

    :cond_25
    move-object/from16 v1, p0

    :goto_17
    and-int/lit8 v20, v12, 0x2

    if-eqz v20, :cond_26

    const/4 v4, 0x3

    invoke-static {v3, v4, v0}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v4

    and-int/lit8 v17, v17, -0x71

    :cond_26
    if-eqz v5, :cond_27

    int-to-float v5, v3

    new-instance v6, Llyiahf/vczjk/di6;

    invoke-direct {v6, v5, v5, v5, v5}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    :cond_27
    if-eqz v7, :cond_28

    goto :goto_18

    :cond_28
    move v3, v8

    :goto_18
    and-int/lit8 v5, v12, 0x10

    if-eqz v5, :cond_2a

    if-nez v3, :cond_29

    sget-object v5, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    goto :goto_19

    :cond_29
    sget-object v5, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    :goto_19
    and-int v17, v17, v19

    goto :goto_1a

    :cond_2a
    move-object v5, v9

    :goto_1a
    if-eqz v10, :cond_2b

    sget-object v7, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    goto :goto_1b

    :cond_2b
    move-object v7, v13

    :goto_1b
    and-int/lit8 v8, v12, 0x40

    if-eqz v8, :cond_2e

    invoke-static {v0}, Llyiahf/vczjk/xy8;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;

    move-result-object v8

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_2c

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v10, v9, :cond_2d

    :cond_2c
    new-instance v10, Llyiahf/vczjk/f22;

    invoke-direct {v10, v8}, Llyiahf/vczjk/f22;-><init>(Llyiahf/vczjk/t02;)V

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2d
    move-object v8, v10

    check-cast v8, Llyiahf/vczjk/f22;

    and-int v9, v17, v18

    goto :goto_1c

    :cond_2e
    move-object v8, v14

    move/from16 v9, v17

    :goto_1c
    if-eqz v15, :cond_2f

    goto :goto_1d

    :cond_2f
    move/from16 v16, p7

    :goto_1d
    and-int/lit16 v10, v12, 0x100

    if-eqz v10, :cond_30

    invoke-static {v0}, Llyiahf/vczjk/rg6;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;

    move-result-object v10

    and-int/2addr v2, v9

    move-object v13, v1

    move-object v14, v4

    move-object/from16 v25, v5

    move-object v15, v6

    move-object/from16 v24, v7

    move-object/from16 v18, v8

    move-object/from16 v20, v10

    move/from16 v19, v16

    move/from16 v16, v3

    move v3, v2

    goto :goto_1e

    :cond_30
    move-object/from16 v20, p8

    move-object v13, v1

    move-object v14, v4

    move-object/from16 v25, v5

    move-object v15, v6

    move-object/from16 v24, v7

    move-object/from16 v18, v8

    move/from16 v19, v16

    move/from16 v16, v3

    move v3, v9

    :goto_1e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    and-int/lit8 v1, v3, 0xe

    or-int/lit16 v1, v1, 0x6000

    and-int/lit8 v2, v3, 0x70

    or-int/2addr v1, v2

    and-int/lit16 v2, v3, 0x380

    or-int/2addr v1, v2

    and-int/lit16 v2, v3, 0x1c00

    or-int/2addr v1, v2

    shr-int/lit8 v2, v3, 0x3

    const/high16 v4, 0x70000

    and-int/2addr v4, v2

    or-int/2addr v1, v4

    const/high16 v4, 0x380000

    and-int/2addr v4, v2

    or-int/2addr v1, v4

    const/high16 v4, 0x1c00000

    and-int/2addr v2, v4

    or-int v28, v1, v2

    shr-int/lit8 v1, v3, 0xc

    and-int/lit8 v1, v1, 0x70

    shr-int/lit8 v2, v3, 0x6

    and-int/lit16 v2, v2, 0x380

    or-int/2addr v1, v2

    shr-int/lit8 v2, v3, 0x12

    and-int/lit16 v2, v2, 0x1c00

    or-int v29, v1, v2

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v17, 0x0

    const/16 v21, 0x0

    const/16 v30, 0x700

    move-object/from16 v26, p9

    move-object/from16 v27, v0

    invoke-static/range {v13 .. v30}, Llyiahf/vczjk/bua;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZZLlyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;ILlyiahf/vczjk/m4;Llyiahf/vczjk/px;Llyiahf/vczjk/n4;Llyiahf/vczjk/nx;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    move-object v1, v13

    move-object v2, v14

    move-object v3, v15

    move/from16 v4, v16

    move-object/from16 v7, v18

    move/from16 v8, v19

    move-object/from16 v9, v20

    move-object/from16 v6, v24

    move-object/from16 v5, v25

    goto :goto_1f

    :cond_31
    move-object/from16 v27, v0

    invoke-virtual/range {v27 .. v27}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object v2, v4

    move-object v3, v6

    move v4, v8

    move-object v5, v9

    move-object v6, v13

    move-object v7, v14

    move/from16 v8, p7

    move-object/from16 v9, p8

    :goto_1f
    invoke-virtual/range {v27 .. v27}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v13

    if-eqz v13, :cond_32

    new-instance v0, Llyiahf/vczjk/pp4;

    move-object/from16 v10, p9

    invoke-direct/range {v0 .. v12}, Llyiahf/vczjk/pp4;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nx;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v13, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_32
    return-void
.end method

.method public static final OooO0oo(Ljava/lang/String;Llyiahf/vczjk/kl5;JZIZLjava/lang/Integer;Llyiahf/vczjk/rn9;Ljava/lang/Integer;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/fv3;IZJJLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;IIII)V
    .locals 49

    move-object/from16 v1, p0

    move/from16 v0, p24

    move/from16 v2, p25

    move/from16 v3, p27

    const-string v4, "markdown"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v4, p23

    check-cast v4, Llyiahf/vczjk/zf1;

    const v5, -0x6a1eef41

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v5, v3, 0x1

    if-eqz v5, :cond_0

    or-int/lit8 v5, v0, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v5, v0, 0xe

    if-nez v5, :cond_2

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/4 v5, 0x4

    goto :goto_0

    :cond_1
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v0

    goto :goto_1

    :cond_2
    move v5, v0

    :goto_1
    and-int/lit8 v8, v3, 0x2

    if-eqz v8, :cond_4

    or-int/lit8 v5, v5, 0x30

    :cond_3
    move-object/from16 v11, p1

    goto :goto_3

    :cond_4
    and-int/lit8 v11, v0, 0x70

    if-nez v11, :cond_3

    move-object/from16 v11, p1

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_5

    const/16 v12, 0x20

    goto :goto_2

    :cond_5
    const/16 v12, 0x10

    :goto_2
    or-int/2addr v5, v12

    :goto_3
    and-int/lit8 v12, v3, 0x4

    if-eqz v12, :cond_7

    or-int/lit16 v5, v5, 0x180

    :cond_6
    move-wide/from16 v14, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v14, v0, 0x380

    if-nez v14, :cond_6

    move-wide/from16 v14, p2

    invoke-virtual {v4, v14, v15}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v16

    if-eqz v16, :cond_8

    const/16 v16, 0x100

    goto :goto_4

    :cond_8
    const/16 v16, 0x80

    :goto_4
    or-int v5, v5, v16

    :goto_5
    and-int/lit8 v16, v3, 0x8

    const/16 v17, 0x400

    if-eqz v16, :cond_a

    or-int/lit16 v5, v5, 0xc00

    :cond_9
    move/from16 v10, p4

    goto :goto_7

    :cond_a
    and-int/lit16 v10, v0, 0x1c00

    if-nez v10, :cond_9

    move/from16 v10, p4

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v19

    if-eqz v19, :cond_b

    const/16 v19, 0x800

    goto :goto_6

    :cond_b
    move/from16 v19, v17

    :goto_6
    or-int v5, v5, v19

    :goto_7
    and-int/lit8 v19, v3, 0x10

    const/16 v20, 0x2000

    const v21, 0xe000

    if-eqz v19, :cond_c

    or-int/lit16 v5, v5, 0x6000

    move/from16 v9, p5

    goto :goto_9

    :cond_c
    and-int v23, v0, v21

    move/from16 v9, p5

    if-nez v23, :cond_e

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v24

    if-eqz v24, :cond_d

    const/16 v24, 0x4000

    goto :goto_8

    :cond_d
    move/from16 v24, v20

    :goto_8
    or-int v5, v5, v24

    :cond_e
    :goto_9
    and-int/lit8 v24, v3, 0x20

    const/high16 v25, 0x10000

    const/high16 v26, 0x70000

    if-eqz v24, :cond_10

    const/high16 v28, 0x30000

    or-int v5, v5, v28

    move/from16 v13, p6

    :cond_f
    const/high16 v28, 0x20000

    goto :goto_b

    :cond_10
    and-int v28, v0, v26

    move/from16 v13, p6

    if-nez v28, :cond_f

    const/high16 v28, 0x20000

    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v29

    if-eqz v29, :cond_11

    move/from16 v29, v28

    goto :goto_a

    :cond_11
    move/from16 v29, v25

    :goto_a
    or-int v5, v5, v29

    :goto_b
    and-int/lit8 v29, v3, 0x40

    const/high16 v30, 0x80000

    const/high16 v31, 0x380000

    const/4 v7, 0x0

    if-eqz v29, :cond_12

    const/high16 v29, 0x180000

    :goto_c
    or-int v5, v5, v29

    goto :goto_d

    :cond_12
    and-int v29, v0, v31

    if-nez v29, :cond_14

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_13

    const/high16 v29, 0x100000

    goto :goto_c

    :cond_13
    move/from16 v29, v30

    goto :goto_c

    :cond_14
    :goto_d
    const/high16 v29, 0x100000

    and-int/lit16 v6, v3, 0x80

    const/high16 v33, 0x1c00000

    if-eqz v6, :cond_15

    const/high16 v34, 0xc00000

    or-int v5, v5, v34

    move-object/from16 v7, p7

    goto :goto_f

    :cond_15
    and-int v34, v0, v33

    move-object/from16 v7, p7

    if-nez v34, :cond_17

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v35

    if-eqz v35, :cond_16

    const/high16 v35, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v35, 0x400000

    :goto_e
    or-int v5, v5, v35

    :cond_17
    :goto_f
    const/high16 v35, 0xe000000

    and-int v36, v0, v35

    if-nez v36, :cond_1a

    and-int/lit16 v0, v3, 0x100

    if-nez v0, :cond_18

    move-object/from16 v0, p8

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v37

    if-eqz v37, :cond_19

    const/high16 v37, 0x4000000

    goto :goto_10

    :cond_18
    move-object/from16 v0, p8

    :cond_19
    const/high16 v37, 0x2000000

    :goto_10
    or-int v5, v5, v37

    goto :goto_11

    :cond_1a
    move-object/from16 v0, p8

    :goto_11
    and-int/lit16 v0, v3, 0x200

    move/from16 v37, v0

    const/high16 v38, 0x70000000

    if-eqz v37, :cond_1b

    const/high16 v39, 0x30000000

    or-int v5, v5, v39

    move-object/from16 v0, p9

    goto :goto_13

    :cond_1b
    and-int v39, p24, v38

    move-object/from16 v0, p9

    if-nez v39, :cond_1d

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v40

    if-eqz v40, :cond_1c

    const/high16 v40, 0x20000000

    goto :goto_12

    :cond_1c
    const/high16 v40, 0x10000000

    :goto_12
    or-int v5, v5, v40

    :cond_1d
    :goto_13
    and-int/lit16 v0, v3, 0x400

    if-eqz v0, :cond_1e

    or-int/lit8 v40, v2, 0x6

    move/from16 v41, v40

    move/from16 v40, v0

    move-object/from16 v0, p10

    goto :goto_15

    :cond_1e
    and-int/lit8 v40, v2, 0xe

    if-nez v40, :cond_20

    move/from16 v40, v0

    move-object/from16 v0, p10

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v41

    if-eqz v41, :cond_1f

    const/16 v41, 0x4

    goto :goto_14

    :cond_1f
    const/16 v41, 0x2

    :goto_14
    or-int v41, v2, v41

    goto :goto_15

    :cond_20
    move/from16 v40, v0

    move-object/from16 v0, p10

    move/from16 v41, v2

    :goto_15
    and-int/lit16 v0, v3, 0x800

    if-eqz v0, :cond_21

    or-int/lit8 v41, v41, 0x30

    move/from16 v42, v0

    :goto_16
    move/from16 v0, v41

    goto :goto_18

    :cond_21
    and-int/lit8 v42, v2, 0x70

    if-nez v42, :cond_23

    move/from16 v42, v0

    move/from16 v0, p11

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v43

    if-eqz v43, :cond_22

    const/16 v18, 0x20

    goto :goto_17

    :cond_22
    const/16 v18, 0x10

    :goto_17
    or-int v41, v41, v18

    goto :goto_16

    :cond_23
    move/from16 v42, v0

    move/from16 v0, p11

    goto :goto_16

    :goto_18
    and-int/lit16 v1, v3, 0x1000

    if-eqz v1, :cond_24

    or-int/lit16 v0, v0, 0x80

    :cond_24
    move/from16 p23, v0

    and-int/lit16 v0, v2, 0x1c00

    if-nez v0, :cond_27

    and-int/lit16 v0, v3, 0x2000

    if-nez v0, :cond_25

    move/from16 v0, p13

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v18

    if-eqz v18, :cond_26

    const/16 v17, 0x800

    goto :goto_19

    :cond_25
    move/from16 v0, p13

    :cond_26
    :goto_19
    or-int v17, p23, v17

    move/from16 v0, v17

    goto :goto_1a

    :cond_27
    move/from16 v0, p13

    move/from16 v0, p23

    :goto_1a
    and-int/lit16 v2, v3, 0x4000

    if-eqz v2, :cond_29

    or-int/lit16 v0, v0, 0x6000

    :cond_28
    move/from16 v17, v0

    move/from16 v0, p14

    goto :goto_1b

    :cond_29
    and-int v17, p25, v21

    if-nez v17, :cond_28

    move/from16 v17, v0

    move/from16 v0, p14

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v18

    if-eqz v18, :cond_2a

    const/16 v20, 0x4000

    :cond_2a
    or-int v17, v17, v20

    :goto_1b
    const v18, 0x8000

    and-int v18, v3, v18

    if-eqz v18, :cond_2c

    const/high16 v20, 0x30000

    or-int v17, v17, v20

    move/from16 p23, v5

    :cond_2b
    move/from16 v20, v6

    move-wide/from16 v5, p15

    goto :goto_1d

    :cond_2c
    and-int v20, p25, v26

    move/from16 p23, v5

    if-nez v20, :cond_2b

    move/from16 v20, v6

    move-wide/from16 v5, p15

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v41

    if-eqz v41, :cond_2d

    move/from16 v41, v28

    goto :goto_1c

    :cond_2d
    move/from16 v41, v25

    :goto_1c
    or-int v17, v17, v41

    :goto_1d
    and-int v25, v3, v25

    if-eqz v25, :cond_2e

    const/high16 v41, 0x180000

    or-int v17, v17, v41

    move-wide/from16 v5, p17

    goto :goto_1f

    :cond_2e
    and-int v41, p25, v31

    move-wide/from16 v5, p17

    if-nez v41, :cond_30

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v41

    if-eqz v41, :cond_2f

    move/from16 v41, v29

    goto :goto_1e

    :cond_2f
    move/from16 v41, v30

    :goto_1e
    or-int v17, v17, v41

    :cond_30
    :goto_1f
    and-int v41, v3, v28

    if-eqz v41, :cond_31

    const/high16 v43, 0xc00000

    or-int v17, v17, v43

    move-object/from16 v0, p19

    goto :goto_21

    :cond_31
    and-int v43, p25, v33

    move-object/from16 v0, p19

    if-nez v43, :cond_33

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v43

    if-eqz v43, :cond_32

    const/high16 v43, 0x800000

    goto :goto_20

    :cond_32
    const/high16 v43, 0x400000

    :goto_20
    or-int v17, v17, v43

    :cond_33
    :goto_21
    const/high16 v43, 0x40000

    and-int v43, v3, v43

    const/high16 v44, 0x6000000

    if-eqz v43, :cond_34

    or-int v17, v17, v44

    move-object/from16 v0, p20

    goto :goto_23

    :cond_34
    and-int v45, p25, v35

    move-object/from16 v0, p20

    if-nez v45, :cond_36

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v45

    if-eqz v45, :cond_35

    const/high16 v45, 0x4000000

    goto :goto_22

    :cond_35
    const/high16 v45, 0x2000000

    :goto_22
    or-int v17, v17, v45

    :cond_36
    :goto_23
    and-int v30, v3, v30

    if-eqz v30, :cond_38

    const/high16 v45, 0x30000000

    :goto_24
    or-int v17, v17, v45

    :cond_37
    move/from16 v0, v17

    goto :goto_25

    :cond_38
    and-int v45, p25, v38

    move-object/from16 v0, p21

    if-nez v45, :cond_37

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v45

    if-eqz v45, :cond_39

    const/high16 v45, 0x20000000

    goto :goto_24

    :cond_39
    const/high16 v45, 0x10000000

    goto :goto_24

    :goto_25
    and-int v17, v3, v29

    if-eqz v17, :cond_3a

    or-int/lit8 v45, p26, 0x6

    move/from16 v46, v45

    move/from16 v45, v2

    goto :goto_27

    :cond_3a
    and-int/lit8 v45, p26, 0xe

    if-nez v45, :cond_3c

    move/from16 v45, v2

    move-object/from16 v2, p22

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v46

    if-eqz v46, :cond_3b

    const/16 v46, 0x4

    goto :goto_26

    :cond_3b
    const/16 v46, 0x2

    :goto_26
    or-int v46, p26, v46

    goto :goto_27

    :cond_3c
    move/from16 v45, v2

    move-object/from16 v2, p22

    move/from16 v46, p26

    :goto_27
    const/16 v2, 0x1000

    if-ne v1, v2, :cond_3e

    const v2, 0x5b6db6db

    and-int v2, p23, v2

    move/from16 v47, v1

    const v1, 0x12492492

    if-ne v2, v1, :cond_3f

    const v1, 0x5b6db6db

    and-int/2addr v1, v0

    const v2, 0x12492492

    if-ne v1, v2, :cond_3f

    and-int/lit8 v1, v46, 0xb

    const/4 v2, 0x2

    if-ne v1, v2, :cond_3f

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_3d

    goto :goto_29

    :cond_3d
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v12, p11

    move-wide/from16 v16, p15

    move-object/from16 v20, p19

    move-object/from16 v21, p20

    move-object/from16 v22, p21

    move-object/from16 v23, p22

    move-object v0, v4

    move-wide/from16 v18, v5

    move-object v8, v7

    move v6, v9

    move v5, v10

    move v7, v13

    move-wide v3, v14

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object/from16 v13, p12

    move/from16 v14, p13

    move/from16 v15, p14

    :goto_28
    move-object v2, v11

    move-object/from16 v11, p10

    goto/16 :goto_49

    :cond_3e
    move/from16 v47, v1

    :cond_3f
    :goto_29
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, p24, 0x1

    if-eqz v1, :cond_43

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_40

    goto :goto_2b

    :cond_40
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit16 v1, v3, 0x100

    if-eqz v1, :cond_41

    const v1, -0xe000001

    and-int v1, p23, v1

    goto :goto_2a

    :cond_41
    move/from16 v1, p23

    :goto_2a
    and-int/lit16 v8, v3, 0x2000

    if-eqz v8, :cond_42

    and-int/lit16 v0, v0, -0x1c01

    :cond_42
    move-object/from16 v12, p9

    move/from16 v19, p11

    move-object/from16 v20, p12

    move/from16 v2, p13

    move/from16 v24, p14

    move-wide/from16 v45, p15

    move-object/from16 v18, p19

    move-object/from16 v25, p20

    move-object/from16 v30, p21

    move-object/from16 v8, p22

    move/from16 v16, v0

    move v3, v1

    move-object/from16 v1, p8

    move-object/from16 v0, p10

    goto/16 :goto_37

    :cond_43
    :goto_2b
    if-eqz v8, :cond_44

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    move-object v11, v1

    :cond_44
    if-eqz v12, :cond_45

    sget-wide v14, Llyiahf/vczjk/n21;->OooOO0:J

    :cond_45
    if-eqz v16, :cond_46

    const/4 v10, 0x0

    :cond_46
    if-eqz v19, :cond_47

    const v1, 0x7fffffff

    move v9, v1

    :cond_47
    if-eqz v24, :cond_48

    const/4 v13, 0x0

    :cond_48
    if-eqz v20, :cond_49

    const/4 v7, 0x0

    :cond_49
    and-int/lit16 v1, v3, 0x100

    if-eqz v1, :cond_4a

    sget-object v1, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rn9;

    const v8, -0xe000001

    and-int v8, p23, v8

    goto :goto_2c

    :cond_4a
    move-object/from16 v1, p8

    move/from16 v8, p23

    :goto_2c
    if-eqz v37, :cond_4b

    const/4 v12, 0x0

    goto :goto_2d

    :cond_4b
    move-object/from16 v12, p9

    :goto_2d
    if-eqz v40, :cond_4c

    const/16 v16, 0x0

    goto :goto_2e

    :cond_4c
    move-object/from16 v16, p10

    :goto_2e
    if-eqz v42, :cond_4d

    const/16 v19, 0x0

    goto :goto_2f

    :cond_4d
    move/from16 v19, p11

    :goto_2f
    if-eqz v47, :cond_4e

    const/16 v20, 0x0

    goto :goto_30

    :cond_4e
    move-object/from16 v20, p12

    :goto_30
    and-int/lit16 v2, v3, 0x2000

    if-eqz v2, :cond_4f

    and-int/lit16 v0, v0, -0x1c01

    const/4 v2, 0x7

    goto :goto_31

    :cond_4f
    move/from16 v2, p13

    :goto_31
    if-eqz v45, :cond_50

    const/16 v24, 0x1

    goto :goto_32

    :cond_50
    move/from16 v24, p14

    :goto_32
    if-eqz v18, :cond_51

    sget-wide v45, Llyiahf/vczjk/n21;->OooO0o0:J

    goto :goto_33

    :cond_51
    move-wide/from16 v45, p15

    :goto_33
    if-eqz v25, :cond_52

    sget-wide v5, Llyiahf/vczjk/n21;->OooO:J

    :cond_52
    if-eqz v41, :cond_53

    const/16 v18, 0x0

    goto :goto_34

    :cond_53
    move-object/from16 v18, p19

    :goto_34
    if-eqz v43, :cond_54

    const/16 v25, 0x0

    goto :goto_35

    :cond_54
    move-object/from16 v25, p20

    :goto_35
    if-eqz v30, :cond_55

    const/16 v30, 0x0

    goto :goto_36

    :cond_55
    move-object/from16 v30, p21

    :goto_36
    move-object/from16 v3, v16

    move/from16 v16, v0

    move-object v0, v3

    move v3, v8

    if-eqz v17, :cond_56

    const/4 v8, 0x0

    goto :goto_37

    :cond_56
    move-object/from16 v8, p22

    :goto_37
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo0()V

    move-wide/from16 p4, v5

    sget-object v5, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/n21;

    iget-wide v5, v5, Llyiahf/vczjk/n21;->OooO00o:J

    move-object/from16 p8, v7

    sget-object v7, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/content/Context;

    move-object/from16 p12, v8

    const v8, -0x85fb72d

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    move/from16 p9, v9

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v9, :cond_61

    const-string v8, "context"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez v20, :cond_57

    invoke-static {v7}, Llyiahf/vczjk/qp3;->OooOoO0(Landroid/content/Context;)Llyiahf/vczjk/ii7;

    move-result-object v8

    :goto_38
    move/from16 p11, v10

    goto :goto_39

    :cond_57
    move-object/from16 v8, v20

    goto :goto_38

    :goto_39
    new-instance v10, Ljava/util/ArrayList;

    move-object/from16 p7, v12

    const/4 v12, 0x3

    invoke-direct {v10, v12}, Ljava/util/ArrayList;-><init>(I)V

    sget-object v12, Landroid/widget/TextView$BufferType;->SPANNABLE:Landroid/widget/TextView$BufferType;

    new-instance v12, Llyiahf/vczjk/lp1;

    invoke-direct {v12}, Llyiahf/vczjk/lp1;-><init>()V

    invoke-virtual {v10, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v12, Llyiahf/vczjk/mp3;

    invoke-direct {v12}, Llyiahf/vczjk/mp3;-><init>()V

    invoke-virtual {v10, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v12, Llyiahf/vczjk/oO0OOo0o;

    move/from16 p10, v13

    const/16 v13, 0xb

    invoke-direct {v12, v7, v13}, Llyiahf/vczjk/oO0OOo0o;-><init>(Ljava/lang/Object;I)V

    new-instance v13, Llyiahf/vczjk/p11;

    invoke-direct {v13, v12, v8}, Llyiahf/vczjk/p11;-><init>(Llyiahf/vczjk/oO0OOo0o;Llyiahf/vczjk/fv3;)V

    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v8, Llyiahf/vczjk/bx8;

    const/4 v12, 0x1

    invoke-direct {v8, v12}, Llyiahf/vczjk/bx8;-><init>(I)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v8, Llyiahf/vczjk/p11;

    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v12

    invoke-virtual {v12}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v12

    iget v12, v12, Landroid/util/DisplayMetrics;->density:F

    new-instance v13, Llyiahf/vczjk/yu2;

    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    move/from16 v17, v12

    const/4 v12, -0x1

    iput v12, v13, Llyiahf/vczjk/yu2;->OooOOO:I

    move-wide/from16 p14, v14

    const/4 v12, 0x4

    int-to-float v14, v12

    mul-float v14, v14, v17

    const/high16 v12, 0x3f000000    # 0.5f

    add-float/2addr v14, v12

    float-to-int v14, v14

    iput v14, v13, Llyiahf/vczjk/yu2;->OooOOO0:I

    const/4 v14, 0x1

    int-to-float v15, v14

    mul-float v15, v15, v17

    add-float/2addr v15, v12

    float-to-int v14, v15

    iput v14, v13, Llyiahf/vczjk/yu2;->OooOOO:I

    new-instance v14, Llyiahf/vczjk/yu2;

    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    iget v15, v13, Llyiahf/vczjk/yu2;->OooOOO0:I

    iput v15, v14, Llyiahf/vczjk/yu2;->OooOOO0:I

    iget v13, v13, Llyiahf/vczjk/yu2;->OooOOO:I

    iput v13, v14, Llyiahf/vczjk/yu2;->OooOOO:I

    invoke-direct {v8, v14}, Llyiahf/vczjk/p11;-><init>(Llyiahf/vczjk/yu2;)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v8, Llyiahf/vczjk/q05;

    const/4 v13, 0x0

    invoke-direct {v8, v2, v13}, Llyiahf/vczjk/q05;-><init>(II)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v8, Landroid/util/TypedValue;

    invoke-direct {v8}, Landroid/util/TypedValue;-><init>()V

    const v13, 0x101009b

    filled-new-array {v13}, [I

    move-result-object v13

    iget v8, v8, Landroid/util/TypedValue;->data:I

    invoke-virtual {v7, v8, v13}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object v8

    const/4 v13, 0x0

    :try_start_0
    invoke-virtual {v8, v13, v13}, Landroid/content/res/TypedArray;->getColor(II)I

    move-result v14
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    new-instance v8, Landroid/util/TypedValue;

    invoke-direct {v8}, Landroid/util/TypedValue;-><init>()V

    const v15, 0x1010031

    filled-new-array {v15}, [I

    move-result-object v15

    iget v8, v8, Landroid/util/TypedValue;->data:I

    invoke-virtual {v7, v8, v15}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object v8

    :try_start_1
    invoke-virtual {v8, v13, v13}, Landroid/content/res/TypedArray;->getColor(II)I

    move-result v15
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    new-instance v8, Llyiahf/vczjk/p11;

    new-instance v13, Llyiahf/vczjk/lg9;

    invoke-direct {v13, v14, v14, v15}, Llyiahf/vczjk/lg9;-><init>(III)V

    invoke-direct {v8, v13}, Llyiahf/vczjk/p11;-><init>(Llyiahf/vczjk/lg9;)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-eqz v24, :cond_58

    new-instance v8, Llyiahf/vczjk/bx8;

    const/4 v13, 0x0

    invoke-direct {v8, v13}, Llyiahf/vczjk/bx8;-><init>(I)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_58
    new-instance v8, Llyiahf/vczjk/q05;

    invoke-static/range {v45 .. v46}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v13

    const/4 v14, 0x1

    invoke-direct {v8, v13, v14}, Llyiahf/vczjk/q05;-><init>(II)V

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v8, Llyiahf/vczjk/nc5;

    move-object/from16 p1, v8

    move-object/from16 p2, v18

    move-object/from16 p3, v25

    move-object/from16 p6, v30

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/nc5;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;JLlyiahf/vczjk/oe3;)V

    move-wide/from16 v13, p4

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v8

    if-nez v8, :cond_60

    new-instance v8, Llyiahf/vczjk/ed5;

    invoke-direct {v8, v10}, Llyiahf/vczjk/ed5;-><init>(Ljava/util/ArrayList;)V

    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :goto_3a
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_59

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v8, v15}, Llyiahf/vczjk/ed5;->OooOO0O(Llyiahf/vczjk/o00O00o0;)V

    goto :goto_3a

    :cond_59
    iget-object v8, v8, Llyiahf/vczjk/ed5;->OooOOOO:Ljava/lang/Object;

    check-cast v8, Ljava/util/ArrayList;

    new-instance v10, Llyiahf/vczjk/ld9;

    const/16 v15, 0x1a

    invoke-direct {v10, v15}, Llyiahf/vczjk/ld9;-><init>(I)V

    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v7

    invoke-virtual {v7}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v7

    iget v7, v7, Landroid/util/DisplayMetrics;->density:F

    new-instance v15, Llyiahf/vczjk/bd5;

    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    move/from16 p1, v12

    const/4 v12, -0x1

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO0o0:I

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO0oO:I

    const/16 v12, 0x8

    int-to-float v12, v12

    mul-float/2addr v12, v7

    add-float v12, v12, p1

    float-to-int v12, v12

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO0Oo:I

    const/16 v12, 0x18

    int-to-float v12, v12

    mul-float/2addr v12, v7

    add-float v12, v12, p1

    float-to-int v12, v12

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO00o:I

    move/from16 v17, v2

    const/4 v12, 0x4

    int-to-float v2, v12

    mul-float/2addr v2, v7

    add-float v2, v2, p1

    float-to-int v2, v2

    iput v2, v15, Llyiahf/vczjk/bd5;->OooO0O0:I

    const/4 v2, 0x1

    int-to-float v12, v2

    mul-float/2addr v12, v7

    add-float v12, v12, p1

    float-to-int v12, v12

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO0OO:I

    int-to-float v12, v2

    mul-float/2addr v12, v7

    add-float v12, v12, p1

    float-to-int v12, v12

    iput v12, v15, Llyiahf/vczjk/bd5;->OooO0o0:I

    const/4 v12, 0x4

    int-to-float v2, v12

    mul-float/2addr v2, v7

    add-float v2, v2, p1

    float-to-int v2, v2

    iput v2, v15, Llyiahf/vczjk/bd5;->OooO0oO:I

    new-instance v2, Llyiahf/vczjk/wc5;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    new-instance v7, Llyiahf/vczjk/tqa;

    const/16 v12, 0x17

    invoke-direct {v7, v12}, Llyiahf/vczjk/tqa;-><init>(I)V

    new-instance v12, Llyiahf/vczjk/tg7;

    move-object/from16 p1, v8

    const/16 v8, 0x14

    invoke-direct {v12, v8}, Llyiahf/vczjk/tg7;-><init>(I)V

    invoke-virtual/range {p1 .. p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :goto_3b
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v37

    if-eqz v37, :cond_5a

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v37

    move-object/from16 p2, v8

    move-object/from16 v8, v37

    check-cast v8, Llyiahf/vczjk/o00O00o0;

    invoke-virtual {v8, v10}, Llyiahf/vczjk/o00O00o0;->OooO0oO(Llyiahf/vczjk/ld9;)V

    invoke-virtual {v8, v15}, Llyiahf/vczjk/o00O00o0;->OooO(Llyiahf/vczjk/bd5;)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/o00O00o0;->OooO0o(Llyiahf/vczjk/wc5;)V

    invoke-virtual {v8, v7}, Llyiahf/vczjk/o00O00o0;->OooOO0(Llyiahf/vczjk/tqa;)V

    invoke-virtual {v8, v12}, Llyiahf/vczjk/o00O00o0;->OooO0oo(Llyiahf/vczjk/tg7;)V

    move-object/from16 v8, p2

    goto :goto_3b

    :cond_5a
    new-instance v8, Llyiahf/vczjk/bd5;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    move-wide/from16 p16, v13

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO00o:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO00o:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0O0:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0O0:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0OO:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0OO:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0Oo:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0Oo:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0o0:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0o0:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0o:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0o:I

    iget v13, v15, Llyiahf/vczjk/bd5;->OooO0oO:I

    iput v13, v8, Llyiahf/vczjk/bd5;->OooO0oO:I

    new-instance v13, Llyiahf/vczjk/sw7;

    iget-object v12, v12, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v12, Ljava/util/HashMap;

    invoke-static {v12}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v12

    const/16 v14, 0x16

    invoke-direct {v13, v12, v14}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    iput-object v13, v2, Llyiahf/vczjk/wc5;->OooO0oO:Llyiahf/vczjk/sw7;

    iget-object v8, v2, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    if-nez v8, :cond_5b

    new-instance v8, Llyiahf/vczjk/pz;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    :cond_5b
    iget-object v8, v2, Llyiahf/vczjk/wc5;->OooO0OO:Llyiahf/vczjk/up3;

    if-nez v8, :cond_5c

    new-instance v8, Llyiahf/vczjk/up3;

    const/16 v12, 0x19

    invoke-direct {v8, v12}, Llyiahf/vczjk/up3;-><init>(I)V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO0OO:Llyiahf/vczjk/up3;

    :cond_5c
    iget-object v8, v2, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    if-nez v8, :cond_5d

    new-instance v8, Llyiahf/vczjk/pp3;

    const/16 v12, 0x13

    invoke-direct {v8, v12}, Llyiahf/vczjk/pp3;-><init>(I)V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    :cond_5d
    iget-object v8, v2, Llyiahf/vczjk/wc5;->OooO0o0:Llyiahf/vczjk/pp3;

    if-nez v8, :cond_5e

    new-instance v8, Llyiahf/vczjk/pp3;

    const/16 v12, 0x12

    invoke-direct {v8, v12}, Llyiahf/vczjk/pp3;-><init>(I)V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO0o0:Llyiahf/vczjk/pp3;

    :cond_5e
    iget-object v8, v2, Llyiahf/vczjk/wc5;->OooO0o:Llyiahf/vczjk/rp3;

    if-nez v8, :cond_5f

    new-instance v8, Llyiahf/vczjk/rp3;

    const/16 v12, 0x12

    invoke-direct {v8, v12}, Llyiahf/vczjk/rp3;-><init>(I)V

    iput-object v8, v2, Llyiahf/vczjk/wc5;->OooO0o:Llyiahf/vczjk/rp3;

    :cond_5f
    new-instance v8, Llyiahf/vczjk/wc5;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO0OO:Llyiahf/vczjk/up3;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO0OO:Llyiahf/vczjk/up3;

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO0o0:Llyiahf/vczjk/pp3;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO0o0:Llyiahf/vczjk/pp3;

    iget-object v12, v2, Llyiahf/vczjk/wc5;->OooO0o:Llyiahf/vczjk/rp3;

    iput-object v12, v8, Llyiahf/vczjk/wc5;->OooO0o:Llyiahf/vczjk/rp3;

    iget-object v2, v2, Llyiahf/vczjk/wc5;->OooO0oO:Llyiahf/vczjk/sw7;

    iput-object v2, v8, Llyiahf/vczjk/wc5;->OooO0oO:Llyiahf/vczjk/sw7;

    new-instance v2, Llyiahf/vczjk/era;

    invoke-direct {v2, v7, v8}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance v8, Llyiahf/vczjk/ad5;

    new-instance v7, Llyiahf/vczjk/ld9;

    invoke-direct {v7, v10}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/ld9;)V

    invoke-static/range {p1 .. p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v10

    invoke-direct {v8, v7, v2, v10}, Llyiahf/vczjk/ad5;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/era;Ljava/util/List;)V

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_3c

    :cond_60
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No plugins were added to this builder. Use #usePlugin method to add them"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :catchall_0
    move-exception v0

    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    throw v0

    :catchall_1
    move-exception v0

    invoke-virtual {v8}, Landroid/content/res/TypedArray;->recycle()V

    throw v0

    :cond_61
    move-wide/from16 p16, p4

    move/from16 v17, v2

    move/from16 p11, v10

    move-object/from16 p7, v12

    move/from16 p10, v13

    move-wide/from16 p14, v14

    :goto_3c
    check-cast v8, Llyiahf/vczjk/vc5;

    const/4 v13, 0x0

    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, -0x85fb59c

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    if-eqz v0, :cond_65

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v7, -0x85fb56a

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    and-int/lit8 v7, v16, 0xe

    const/4 v12, 0x4

    if-ne v7, v12, :cond_62

    const/4 v7, 0x1

    goto :goto_3d

    :cond_62
    const/4 v7, 0x0

    :goto_3d
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v7, :cond_63

    if-ne v10, v9, :cond_64

    :cond_63
    new-instance v10, Llyiahf/vczjk/rc5;

    invoke-direct {v10, v0}, Llyiahf/vczjk/rc5;-><init>(Llyiahf/vczjk/le3;)V

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_64
    check-cast v10, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x7

    const/4 v12, 0x0

    invoke-static {v2, v13, v12, v10, v7}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-interface {v2, v11}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    goto :goto_3e

    :cond_65
    const/4 v13, 0x0

    move-object v2, v11

    :goto_3e
    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, -0x85fb4de

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    and-int/lit16 v7, v3, 0x380

    const/16 v10, 0x100

    if-ne v7, v10, :cond_66

    const/4 v14, 0x1

    goto :goto_3f

    :cond_66
    const/4 v14, 0x0

    :goto_3f
    and-int v7, v3, v35

    xor-int v7, v7, v44

    const/high16 v10, 0x4000000

    if-le v7, v10, :cond_67

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_68

    :cond_67
    and-int v7, v3, v44

    if-ne v7, v10, :cond_69

    :cond_68
    const/4 v7, 0x1

    goto :goto_40

    :cond_69
    const/4 v7, 0x0

    :goto_40
    or-int/2addr v7, v14

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v10

    or-int/2addr v7, v10

    and-int v10, v3, v38

    const/high16 v12, 0x20000000

    if-ne v10, v12, :cond_6a

    const/4 v14, 0x1

    goto :goto_41

    :cond_6a
    const/4 v14, 0x0

    :goto_41
    or-int/2addr v7, v14

    and-int v10, v3, v33

    const/high16 v12, 0x800000

    if-ne v10, v12, :cond_6b

    const/4 v14, 0x1

    goto :goto_42

    :cond_6b
    const/4 v14, 0x0

    :goto_42
    or-int/2addr v7, v14

    and-int v10, v3, v21

    const/16 v12, 0x4000

    if-ne v10, v12, :cond_6c

    const/4 v14, 0x1

    goto :goto_43

    :cond_6c
    const/4 v14, 0x0

    :goto_43
    or-int/2addr v7, v14

    and-int v10, v3, v26

    move/from16 v12, v28

    if-ne v10, v12, :cond_6d

    const/4 v14, 0x1

    goto :goto_44

    :cond_6d
    const/4 v14, 0x0

    :goto_44
    or-int/2addr v7, v14

    and-int/lit16 v10, v3, 0x1c00

    const/16 v12, 0x800

    if-ne v10, v12, :cond_6e

    const/4 v14, 0x1

    goto :goto_45

    :cond_6e
    const/4 v14, 0x0

    :goto_45
    or-int/2addr v7, v14

    and-int v3, v3, v31

    move/from16 v10, v29

    if-ne v3, v10, :cond_6f

    const/4 v3, 0x1

    goto :goto_46

    :cond_6f
    const/4 v3, 0x0

    :goto_46
    or-int/2addr v3, v7

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v3, :cond_71

    if-ne v7, v9, :cond_70

    goto :goto_47

    :cond_70
    move-object/from16 v12, p7

    move-object/from16 v3, p8

    move/from16 v9, p9

    move/from16 v13, p10

    move/from16 v10, p11

    move-wide/from16 v14, p14

    goto :goto_48

    :cond_71
    :goto_47
    new-instance v3, Llyiahf/vczjk/oc5;

    move-wide/from16 p2, p14

    move-object/from16 p4, v1

    move-object/from16 p1, v3

    move-wide/from16 p5, v5

    invoke-direct/range {p1 .. p11}, Llyiahf/vczjk/oc5;-><init>(JLlyiahf/vczjk/rn9;JLjava/lang/Integer;Ljava/lang/Integer;IZZ)V

    move-object/from16 v7, p1

    move-wide/from16 v14, p2

    move-object/from16 v12, p7

    move-object/from16 v3, p8

    move/from16 v9, p9

    move/from16 v13, p10

    move/from16 v10, p11

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_48
    check-cast v7, Llyiahf/vczjk/oe3;

    move-object/from16 p10, v0

    const/4 v0, 0x0

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v0, Llyiahf/vczjk/pc5;

    move-object/from16 p3, p0

    move-object/from16 p5, p12

    move-object/from16 p1, v0

    move-object/from16 p7, v1

    move-wide/from16 p8, v5

    move-object/from16 p2, v8

    move/from16 p6, v9

    move/from16 p4, v19

    invoke-direct/range {p1 .. p9}, Llyiahf/vczjk/pc5;-><init>(Llyiahf/vczjk/vc5;Ljava/lang/String;ZLlyiahf/vczjk/oe3;ILlyiahf/vczjk/rn9;J)V

    move-object/from16 v32, p5

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object/from16 p3, v0

    move-object/from16 p2, v2

    move-object/from16 p4, v4

    move/from16 p5, v5

    move/from16 p6, v6

    move-object/from16 p1, v7

    invoke-static/range {p1 .. p6}, Landroidx/compose/ui/viewinterop/OooO00o;->OooO00o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v0, p4

    move-object v8, v3

    move v6, v9

    move v5, v10

    move-object v10, v12

    move v7, v13

    move-wide v3, v14

    move/from16 v14, v17

    move/from16 v12, v19

    move-object/from16 v13, v20

    move/from16 v15, v24

    move-object/from16 v21, v25

    move-object/from16 v22, v30

    move-object/from16 v23, v32

    move-wide/from16 v16, v45

    move-object v9, v1

    move-object/from16 v20, v18

    move-wide/from16 v18, p16

    goto/16 :goto_28

    :goto_49
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_72

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/qc5;

    move/from16 v24, p24

    move/from16 v25, p25

    move/from16 v26, p26

    move/from16 v27, p27

    move-object/from16 v48, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v27}, Llyiahf/vczjk/qc5;-><init>(Ljava/lang/String;Llyiahf/vczjk/kl5;JZIZLjava/lang/Integer;Llyiahf/vczjk/rn9;Ljava/lang/Integer;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/fv3;IZJJLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;IIII)V

    move-object/from16 v1, v48

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_72
    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/cc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 49

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    const/4 v0, 0x0

    move-object/from16 v15, p4

    check-cast v15, Llyiahf/vczjk/zf1;

    const v7, 0x48e80ed0    # 475254.5f

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    const/4 v7, 0x4

    goto :goto_0

    :cond_0
    const/4 v7, 0x2

    :goto_0
    or-int v7, p5, v7

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    const/16 v9, 0x10

    if-eqz v8, :cond_1

    const/16 v8, 0x20

    goto :goto_1

    :cond_1
    move v8, v9

    :goto_1
    or-int/2addr v7, v8

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_2

    const/16 v8, 0x100

    goto :goto_2

    :cond_2
    const/16 v8, 0x80

    :goto_2
    or-int/2addr v7, v8

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    const/16 v8, 0x800

    goto :goto_3

    :cond_3
    const/16 v8, 0x400

    :goto_3
    or-int/2addr v7, v8

    and-int/lit16 v8, v7, 0x493

    const/16 v13, 0x492

    if-ne v8, v13, :cond_5

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v1

    move-object v5, v2

    goto/16 :goto_1c

    :cond_5
    :goto_4
    sget-object v8, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/content/Context;

    invoke-static {v8}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v8

    const-wide v13, 0xff757575L

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v30

    sget-object v13, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v14, 0x3f800000    # 1.0f

    invoke-static {v13, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v10

    int-to-float v9, v9

    const/16 v11, 0x8

    int-to-float v11, v11

    invoke-static {v10, v9, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v10

    const/16 v11, 0xc

    int-to-float v11, v11

    invoke-static {v11}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/ap9;

    iget-wide v5, v11, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v11, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v10, v5, v6, v11}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    const v6, -0x615d173a

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v10, :cond_6

    if-ne v11, v6, :cond_7

    :cond_6
    new-instance v11, Llyiahf/vczjk/oo0oO0;

    const/16 v10, 0x17

    invoke-direct {v11, v10, v8, v1}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v15, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v11, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v11}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v8, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v11, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v15, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v18, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v18, v8

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v0, :cond_8

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v15, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    move/from16 v20, v7

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v14, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_a

    goto :goto_6

    :cond_9
    move/from16 v20, v7

    :goto_6
    invoke-static {v11, v15, v11, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v15, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-static {v13, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v11

    sget-object v14, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    move/from16 v21, v9

    const/4 v9, 0x0

    invoke-static {v14, v5, v15, v9}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v9, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v15, v11}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v22, v13

    iget-boolean v13, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_b

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_b
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v5, v15, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_c

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v5, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_d

    :cond_c
    invoke-static {v9, v15, v9, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    invoke-static {v11, v15, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v5, v1, Llyiahf/vczjk/cc6;->OooO0O0:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getName()Ljava/lang/String;

    move-result-object v5

    sget-object v9, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/n6a;

    iget-object v11, v11, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    sget-object v37, Llyiahf/vczjk/ib3;->OooOOo0:Llyiahf/vczjk/ib3;

    const/16 v44, 0x0

    const/16 v45, 0x0

    const-wide/16 v33, 0x0

    const-wide/16 v35, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const-wide/16 v40, 0x0

    const-wide/16 v42, 0x0

    const v46, 0xfffffb

    move-object/from16 v32, v11

    invoke-static/range {v32 .. v46}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v25

    const/16 v24, 0x0

    const/16 v27, 0x0

    move-object v11, v8

    const/4 v8, 0x0

    move-object v14, v9

    move-object v13, v10

    const-wide/16 v9, 0x0

    move-object/from16 v23, v11

    move-object/from16 v26, v12

    const-wide/16 v11, 0x0

    move-object/from16 v28, v13

    const/4 v13, 0x0

    move-object/from16 v29, v14

    const/4 v14, 0x0

    move-object/from16 v33, v26

    const/16 v32, 0x100

    move-object/from16 v26, v15

    const-wide/16 v15, 0x0

    const/16 v34, 0x800

    const/16 v17, 0x0

    move-object/from16 v36, v18

    const/high16 v35, 0x3f800000    # 1.0f

    const-wide/16 v18, 0x0

    move/from16 v37, v20

    const/16 v20, 0x0

    move/from16 v38, v21

    const/16 v21, 0x0

    move-object/from16 v39, v22

    const/16 v22, 0x0

    move-object/from16 v40, v23

    const/16 v23, 0x0

    move-object/from16 v41, v28

    const/16 v28, 0x0

    move-object/from16 v42, v29

    const v29, 0x1fffe

    move-object/from16 v32, v6

    move-object v1, v7

    move/from16 v4, v38

    move-object/from16 v3, v39

    move-object/from16 v2, v40

    move-object/from16 v6, v41

    move-object/from16 v47, v42

    move-object v7, v5

    move-object/from16 v5, v33

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v26

    const/4 v9, 0x0

    invoke-static {v9, v15}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    sget-object v7, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v8, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v9, 0x30

    invoke-static {v8, v7, v15, v9}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v10

    iget v11, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v15, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_e

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_e
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v10, v15, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v10, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_f

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v10, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_10

    :cond_f
    invoke-static {v11, v15, v11, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    invoke-static {v13, v15, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move v10, v9

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v11, Llyiahf/vczjk/ht6;->OooO00o:Llyiahf/vczjk/qv3;

    if-eqz v11, :cond_11

    move-object/from16 v24, v7

    :goto_9
    move-object v7, v11

    goto/16 :goto_a

    :cond_11
    new-instance v16, Llyiahf/vczjk/pv3;

    const-wide/16 v22, 0x0

    const/16 v26, 0x60

    const-string v17, "Filled.Person"

    const/high16 v18, 0x41c00000    # 24.0f

    const/high16 v19, 0x41c00000    # 24.0f

    const/high16 v20, 0x41c00000    # 24.0f

    const/high16 v21, 0x41c00000    # 24.0f

    const/16 v24, 0x0

    const/16 v25, 0x0

    invoke-direct/range {v16 .. v26}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    move-object/from16 v11, v16

    sget v12, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v12, Llyiahf/vczjk/gx8;

    sget-wide v13, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v12, v13, v14}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v13, Llyiahf/vczjk/jq;

    const/4 v14, 0x1

    invoke-direct {v13, v14}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v14, 0x41400000    # 12.0f

    invoke-virtual {v13, v14, v14}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v21, 0x40800000    # 4.0f

    const/high16 v22, -0x3f800000    # -4.0f

    const v17, 0x400d70a4    # 2.21f

    const/16 v18, 0x0

    const/high16 v19, 0x40800000    # 4.0f

    const v20, -0x401ae148    # -1.79f

    move-object/from16 v16, v13

    invoke-virtual/range {v16 .. v22}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const v10, -0x401ae148    # -1.79f

    const/high16 v14, -0x3f800000    # -4.0f

    invoke-virtual {v13, v10, v14, v14, v14}, Llyiahf/vczjk/jq;->OooOO0o(FFFF)V

    const v10, 0x3fe51eb8    # 1.79f

    move-object/from16 v24, v7

    const/high16 v7, 0x40800000    # 4.0f

    invoke-virtual {v13, v14, v10, v14, v7}, Llyiahf/vczjk/jq;->OooOO0o(FFFF)V

    invoke-virtual {v13, v10, v7, v7, v7}, Llyiahf/vczjk/jq;->OooOO0o(FFFF)V

    invoke-virtual {v13}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x41600000    # 14.0f

    const/high16 v10, 0x41400000    # 12.0f

    invoke-virtual {v13, v10, v7}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v21, -0x3f000000    # -8.0f

    const/high16 v22, 0x40800000    # 4.0f

    const v17, -0x3fd51eb8    # -2.67f

    const/high16 v19, -0x3f000000    # -8.0f

    const v20, 0x3fab851f    # 1.34f

    invoke-virtual/range {v16 .. v22}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v7, 0x40000000    # 2.0f

    invoke-virtual {v13, v7}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v7, 0x41800000    # 16.0f

    invoke-virtual {v13, v7}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v7, -0x40000000    # -2.0f

    invoke-virtual {v13, v7}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v22, -0x3f800000    # -4.0f

    const/16 v17, 0x0

    const v18, -0x3fd5c28f    # -2.66f

    const v19, -0x3f5570a4    # -5.33f

    const/high16 v20, -0x3f800000    # -4.0f

    invoke-virtual/range {v16 .. v22}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    invoke-virtual {v13}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v7, v13, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v11, v7, v12}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v11}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v11

    sput-object v11, Llyiahf/vczjk/ht6;->OooO00o:Llyiahf/vczjk/qv3;

    goto/16 :goto_9

    :goto_a
    const/4 v14, 0x0

    move-object v10, v8

    const-string v8, "Author"

    const/16 v13, 0xdb0

    move-object v12, v15

    move-object v15, v10

    move-wide/from16 v10, v30

    invoke-static/range {v7 .. v14}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v9, 0x0

    invoke-static {v9, v12}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v7, p0

    iget-object v8, v7, Llyiahf/vczjk/cc6;->OooO00o:Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;

    invoke-virtual {v8}, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;->getAuthor()Ljava/lang/String;

    move-result-object v7

    move-object/from16 v9, v47

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/n6a;

    iget-object v13, v13, Llyiahf/vczjk/n6a;->OooOOO0:Llyiahf/vczjk/rn9;

    move-object/from16 v14, v24

    const/16 v24, 0x0

    const/16 v27, 0x180

    move-object/from16 v16, v8

    const/4 v8, 0x0

    move-object/from16 v29, v9

    move-wide v9, v10

    move-object/from16 v26, v12

    const-wide/16 v11, 0x0

    move-object/from16 v25, v13

    const/4 v13, 0x0

    move-object/from16 v17, v14

    const/4 v14, 0x0

    move-object/from16 v18, v15

    move-object/from16 v19, v16

    const-wide/16 v15, 0x0

    move-object/from16 v20, v17

    const/16 v17, 0x0

    move-object/from16 v21, v18

    move-object/from16 v22, v19

    const-wide/16 v18, 0x0

    move-object/from16 v23, v20

    const/16 v20, 0x0

    move-object/from16 v28, v21

    const/16 v21, 0x0

    move-object/from16 v30, v22

    const/16 v22, 0x0

    move-object/from16 v31, v23

    const/16 v23, 0x0

    move-object/from16 v33, v28

    const/16 v28, 0x0

    move-object/from16 v42, v29

    const v29, 0x1fffa

    move/from16 v38, v4

    move-object/from16 v4, v31

    move-object/from16 v48, v42

    move-object/from16 v31, v30

    move-object/from16 v30, v1

    move-object/from16 v1, v33

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-wide v10, v9

    move-object/from16 v15, v26

    const/4 v14, 0x1

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v9, 0x0

    invoke-static {v9, v15}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    const/16 v7, 0x30

    invoke-static {v1, v4, v15, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v1

    iget v4, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v15, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_12

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_b

    :cond_12
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_b
    invoke-static {v1, v15, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_14

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_13

    goto :goto_d

    :cond_13
    :goto_c
    move-object/from16 v1, v30

    goto :goto_e

    :cond_14
    :goto_d
    invoke-static {v4, v15, v4, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_c

    :goto_e
    invoke-static {v8, v15, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move/from16 v4, v38

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOOO()Llyiahf/vczjk/qv3;

    move-result-object v7

    const/4 v14, 0x0

    const-string v8, "Version"

    const/16 v13, 0xdb0

    move-object v12, v15

    invoke-static/range {v7 .. v14}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v9, 0x0

    invoke-static {v9, v15}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-virtual/range {v31 .. v31}, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;->getVersion()I

    move-result v4

    const-string v7, "v"

    invoke-static {v4, v7}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v7

    move-object/from16 v4, v48

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/n6a;

    iget-object v8, v8, Llyiahf/vczjk/n6a;->OooOOO0:Llyiahf/vczjk/rn9;

    const/16 v24, 0x0

    const/16 v27, 0x180

    move-object/from16 v25, v8

    const/4 v8, 0x0

    move-wide v9, v10

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v26, v15

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v28, 0x0

    const v29, 0x1fffa

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v26

    const/4 v14, 0x1

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v9, 0x0

    invoke-static {v9, v15}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v7, p0

    iget-object v8, v7, Llyiahf/vczjk/cc6;->OooO0O0:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v8}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getDescription()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/n6a;

    iget-object v4, v4, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v24, 0x0

    const/16 v27, 0x0

    move-object v7, v8

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v26, v15

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v28, 0x0

    const v29, 0x1fffe

    move-object/from16 v25, v4

    move-object/from16 v4, p0

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v26

    const/4 v9, 0x0

    invoke-static {v9, v15}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v3, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    move-object/from16 v8, v36

    invoke-static {v8, v9}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v8

    iget v9, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v15, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_15

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_f

    :cond_15
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_f
    invoke-static {v8, v15, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_16

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_17

    :cond_16
    invoke-static {v9, v15, v9, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_17
    invoke-static {v7, v15, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v1, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    iget-boolean v2, v4, Llyiahf/vczjk/cc6;->OooO0Oo:Z

    if-nez v2, :cond_1b

    const v2, -0x27837744

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v3, v1}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const v0, -0x615d173a

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v0, v37, 0x70

    const/16 v1, 0x20

    if-ne v0, v1, :cond_18

    const/4 v0, 0x1

    goto :goto_10

    :cond_18
    const/4 v0, 0x0

    :goto_10
    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_1a

    move-object/from16 v2, v32

    if-ne v1, v2, :cond_19

    goto :goto_11

    :cond_19
    move-object/from16 v5, p1

    const/4 v0, 0x0

    goto :goto_12

    :cond_1a
    :goto_11
    new-instance v1, Llyiahf/vczjk/yb6;

    move-object/from16 v5, p1

    const/4 v0, 0x0

    invoke-direct {v1, v5, v4, v0}, Llyiahf/vczjk/yb6;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/cc6;I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_12
    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v14, Llyiahf/vczjk/gb1;->OooO0Oo:Llyiahf/vczjk/a91;

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/high16 v16, 0x30000000

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/bua;->OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v3, p2

    :goto_13
    const/4 v14, 0x1

    goto/16 :goto_1b

    :cond_1b
    move-object/from16 v5, p1

    move-object/from16 v2, v32

    const v6, -0x27796cee

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v6, v4, Llyiahf/vczjk/cc6;->OooO0o0:Z

    if-eqz v6, :cond_1f

    const v6, -0x27791a96

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v3, v1}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const v0, -0x615d173a

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move/from16 v6, v37

    and-int/lit16 v0, v6, 0x1c00

    const/16 v1, 0x800

    if-ne v0, v1, :cond_1c

    const/4 v0, 0x1

    goto :goto_14

    :cond_1c
    const/4 v0, 0x0

    :goto_14
    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_1e

    if-ne v1, v2, :cond_1d

    goto :goto_15

    :cond_1d
    move-object/from16 v0, p3

    goto :goto_16

    :cond_1e
    :goto_15
    new-instance v1, Llyiahf/vczjk/yb6;

    move-object/from16 v0, p3

    const/4 v14, 0x1

    invoke-direct {v1, v0, v4, v14}, Llyiahf/vczjk/yb6;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/cc6;I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_16
    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/le3;

    const/4 v1, 0x0

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v14, Llyiahf/vczjk/gb1;->OooO0o0:Llyiahf/vczjk/a91;

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/high16 v16, 0x30000000

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/bua;->OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v3, p2

    const/4 v0, 0x0

    goto :goto_1a

    :cond_1f
    move/from16 v6, v37

    const v7, -0x276eaf7f

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v3, v1}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const v0, -0x615d173a

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v0, v6, 0x380

    const/16 v1, 0x100

    if-ne v0, v1, :cond_20

    const/4 v9, 0x1

    goto :goto_17

    :cond_20
    const/4 v9, 0x0

    :goto_17
    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr v0, v9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_22

    if-ne v1, v2, :cond_21

    goto :goto_18

    :cond_21
    move-object/from16 v3, p2

    goto :goto_19

    :cond_22
    :goto_18
    new-instance v1, Llyiahf/vczjk/yb6;

    move-object/from16 v3, p2

    const/4 v0, 0x2

    invoke-direct {v1, v3, v4, v0}, Llyiahf/vczjk/yb6;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/cc6;I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_19
    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/le3;

    const/4 v0, 0x0

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v14, Llyiahf/vczjk/gb1;->OooO0o:Llyiahf/vczjk/a91;

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/high16 v16, 0x30000000

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/bua;->OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1a
    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_13

    :goto_1b
    invoke-static {v15, v14, v14, v14}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_1c
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_23

    new-instance v0, Llyiahf/vczjk/d5;

    move-object v1, v4

    move-object v2, v5

    move-object/from16 v4, p3

    move/from16 v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/d5;-><init>(Llyiahf/vczjk/cc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;I)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_23
    return-void
.end method

.method public static final OooOO0O(Llyiahf/vczjk/bi6;Llyiahf/vczjk/gc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 14

    move-object/from16 v10, p5

    check-cast v10, Llyiahf/vczjk/zf1;

    const v0, -0x786b6da4

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p6, v0

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    const/16 v2, 0x20

    goto :goto_1

    :cond_1
    const/16 v2, 0x10

    :goto_1
    or-int/2addr v0, v2

    move-object/from16 v2, p2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/16 v4, 0x100

    if-eqz v3, :cond_2

    move v3, v4

    goto :goto_2

    :cond_2
    const/16 v3, 0x80

    :goto_2
    or-int/2addr v0, v3

    move-object/from16 v3, p3

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v6, 0x800

    if-eqz v5, :cond_3

    move v5, v6

    goto :goto_3

    :cond_3
    const/16 v5, 0x400

    :goto_3
    or-int/2addr v0, v5

    move-object/from16 v5, p4

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    const/16 v8, 0x4000

    if-eqz v7, :cond_4

    move v7, v8

    goto :goto_4

    :cond_4
    const/16 v7, 0x2000

    :goto_4
    or-int/2addr v0, v7

    and-int/lit16 v7, v0, 0x2493

    const/16 v9, 0x2492

    if-ne v7, v9, :cond_6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v7

    if-nez v7, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_9

    :cond_6
    :goto_5
    sget-object v7, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v7, p0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v7

    const v9, -0x48fade91

    invoke-virtual {v10, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    and-int/lit16 v11, v0, 0x380

    const/4 v12, 0x1

    const/4 v13, 0x0

    if-ne v11, v4, :cond_7

    move v4, v12

    goto :goto_6

    :cond_7
    move v4, v13

    :goto_6
    or-int/2addr v4, v9

    and-int/lit16 v9, v0, 0x1c00

    if-ne v9, v6, :cond_8

    move v6, v12

    goto :goto_7

    :cond_8
    move v6, v13

    :goto_7
    or-int/2addr v4, v6

    const v6, 0xe000

    and-int/2addr v0, v6

    if-ne v0, v8, :cond_9

    goto :goto_8

    :cond_9
    move v12, v13

    :goto_8
    or-int v0, v4, v12

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_a

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v0, :cond_b

    :cond_a
    new-instance v0, Llyiahf/vczjk/m60;

    const/4 v5, 0x7

    move-object v1, p1

    move-object/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v4, v0

    :cond_b
    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v0, v7

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v11, 0x0

    const/16 v12, 0x1fe

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_9
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_c

    new-instance v0, Llyiahf/vczjk/nu3;

    const/4 v7, 0x3

    move-object v1, p0

    move-object v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p6

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/nu3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    if-nez p1, :cond_0

    return-object p0

    :cond_0
    const-string v0, ": "

    invoke-static {p0, v0, p1}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOOO(Llyiahf/vczjk/ie2;J)Z
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v1, v0, Llyiahf/vczjk/b04;->OoooOoO:Llyiahf/vczjk/cf9;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    const-wide/16 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/v16;->OoooOO0(J)J

    move-result-wide v0

    const/16 v2, 0x20

    shr-long v3, v0, v2

    long-to-int v3, v3

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    iget-wide v6, p0, Llyiahf/vczjk/ie2;->OooOoo:J

    shr-long v8, v6, v2

    long-to-int p0, v8

    int-to-float p0, p0

    add-float/2addr p0, v3

    and-long/2addr v6, v4

    long-to-int v1, v6

    int-to-float v1, v1

    add-float/2addr v1, v0

    shr-long v6, p1, v2

    long-to-int v2, v6

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    cmpg-float v3, v3, v2

    if-gtz v3, :cond_2

    cmpg-float p0, v2, p0

    if-gtz p0, :cond_2

    and-long p0, p1, v4

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    cmpg-float p1, v0, p0

    if-gtz p1, :cond_2

    cmpg-float p0, p0, v1

    if-gtz p0, :cond_2

    const/4 p0, 0x1

    return p0

    :cond_2
    :goto_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOOO0(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    if-nez p0, :cond_0

    const-string p0, "[N/A]"

    return-object p0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/16 v1, 0x1f4

    if-gt v0, v1, :cond_1

    goto :goto_0

    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const/4 v2, 0x0

    invoke-virtual {p0, v2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "]...["

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    sub-int/2addr v2, v1

    invoke-virtual {p0, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    :goto_0
    const-string v0, "\""

    invoke-static {v0, p0, v0}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOo(Ljava/lang/reflect/Type;)V
    .locals 1

    instance-of v0, p0, Ljava/lang/Class;

    if-eqz v0, :cond_1

    check-cast p0, Ljava/lang/Class;

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result p0

    if-nez p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p0, 0x1

    :goto_1
    invoke-static {p0}, Llyiahf/vczjk/qqa;->OooOo00(Z)V

    return-void
.end method

.method public static OooOOo0(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;
    .locals 3

    instance-of v0, p0, Ljava/lang/Class;

    if-eqz v0, :cond_1

    check-cast p0, Ljava/lang/Class;

    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/rk3;

    invoke-virtual {p0}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/mc4;->OooOOo0(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/rk3;-><init>(Ljava/lang/reflect/Type;)V

    return-object v0

    :cond_0
    return-object p0

    :cond_1
    instance-of v0, p0, Ljava/lang/reflect/ParameterizedType;

    if-eqz v0, :cond_2

    check-cast p0, Ljava/lang/reflect/ParameterizedType;

    new-instance v0, Llyiahf/vczjk/sk3;

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getOwnerType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object v2

    check-cast v2, Ljava/lang/Class;

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-direct {v0, v1, v2, p0}, Llyiahf/vczjk/sk3;-><init>(Ljava/lang/reflect/Type;Ljava/lang/Class;[Ljava/lang/reflect/Type;)V

    return-object v0

    :cond_2
    instance-of v0, p0, Ljava/lang/reflect/GenericArrayType;

    if-eqz v0, :cond_3

    check-cast p0, Ljava/lang/reflect/GenericArrayType;

    new-instance v0, Llyiahf/vczjk/rk3;

    invoke-interface {p0}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/rk3;-><init>(Ljava/lang/reflect/Type;)V

    return-object v0

    :cond_3
    instance-of v0, p0, Ljava/lang/reflect/WildcardType;

    if-eqz v0, :cond_4

    check-cast p0, Ljava/lang/reflect/WildcardType;

    new-instance v0, Llyiahf/vczjk/tk3;

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Llyiahf/vczjk/tk3;-><init>([Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V

    return-object v0

    :cond_4
    return-object p0
.end method

.method public static OooOOoo(III)V
    .locals 4

    const-string v0, "fromIndex: "

    if-ltz p0, :cond_1

    if-gt p1, p2, :cond_1

    if-gt p0, p1, :cond_0

    return-void

    :cond_0
    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string v1, " > toIndex: "

    invoke-static {p0, p1, v0, v1}, Llyiahf/vczjk/u81;->OooO0oo(IILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    const-string v2, ", toIndex: "

    const-string v3, ", size: "

    invoke-static {p0, p1, v0, v2, v3}, Llyiahf/vczjk/ii5;->OooOOO0(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p0

    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public static OooOo(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p0, Ljava/lang/Class;

    if-eqz v1, :cond_1

    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p0

    return p0

    :cond_1
    instance-of v1, p0, Ljava/lang/reflect/ParameterizedType;

    const/4 v2, 0x0

    if-eqz v1, :cond_4

    instance-of v1, p1, Ljava/lang/reflect/ParameterizedType;

    if-nez v1, :cond_2

    return v2

    :cond_2
    check-cast p0, Ljava/lang/reflect/ParameterizedType;

    check-cast p1, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getOwnerType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getOwnerType()Ljava/lang/reflect/Type;

    move-result-object v3

    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p1

    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_3

    return v0

    :cond_3
    return v2

    :cond_4
    instance-of v1, p0, Ljava/lang/reflect/GenericArrayType;

    if-eqz v1, :cond_6

    instance-of v0, p1, Ljava/lang/reflect/GenericArrayType;

    if-nez v0, :cond_5

    return v2

    :cond_5
    check-cast p0, Ljava/lang/reflect/GenericArrayType;

    check-cast p1, Ljava/lang/reflect/GenericArrayType;

    invoke-interface {p0}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-interface {p1}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->OooOo(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

    move-result p0

    return p0

    :cond_6
    instance-of v1, p0, Ljava/lang/reflect/WildcardType;

    if-eqz v1, :cond_9

    instance-of v1, p1, Ljava/lang/reflect/WildcardType;

    if-nez v1, :cond_7

    return v2

    :cond_7
    check-cast p0, Ljava/lang/reflect/WildcardType;

    check-cast p1, Ljava/lang/reflect/WildcardType;

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-interface {p1}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v3

    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_8

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-interface {p1}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object p1

    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_8

    return v0

    :cond_8
    return v2

    :cond_9
    instance-of v1, p0, Ljava/lang/reflect/TypeVariable;

    if-eqz v1, :cond_b

    instance-of v1, p1, Ljava/lang/reflect/TypeVariable;

    if-nez v1, :cond_a

    return v2

    :cond_a
    check-cast p0, Ljava/lang/reflect/TypeVariable;

    check-cast p1, Ljava/lang/reflect/TypeVariable;

    invoke-interface {p0}, Ljava/lang/reflect/TypeVariable;->getGenericDeclaration()Ljava/lang/reflect/GenericDeclaration;

    move-result-object v1

    invoke-interface {p1}, Ljava/lang/reflect/TypeVariable;->getGenericDeclaration()Ljava/lang/reflect/GenericDeclaration;

    move-result-object v3

    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_b

    invoke-interface {p0}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_b

    return v0

    :cond_b
    return v2
.end method

.method public static OooOo00(II)I
    .locals 5

    int-to-long v0, p0

    int-to-long v2, p1

    sub-long/2addr v0, v2

    long-to-int v2, v0

    int-to-long v3, v2

    cmp-long v0, v0, v3

    if-nez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    const-string v1, "checkedSubtract"

    invoke-static {p0, p1, v1, v0}, Llyiahf/vczjk/jp8;->OooOOOO(IILjava/lang/String;Z)V

    return v2
.end method

.method public static final OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;
    .locals 5

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, 0x698e223e

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v0, p0, Llyiahf/vczjk/om3;

    if-eqz v0, :cond_2

    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/Context;

    check-cast p0, Llyiahf/vczjk/om3;

    invoke-interface {p0}, Llyiahf/vczjk/om3;->getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;

    move-result-object p0

    const-string v1, "context"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "delegateFactory"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_0
    instance-of v1, v0, Landroid/content/ContextWrapper;

    if-eqz v1, :cond_1

    instance-of v1, v0, Landroidx/activity/ComponentActivity;

    if-eqz v1, :cond_0

    check-cast v0, Landroidx/activity/ComponentActivity;

    const-class v1, Llyiahf/vczjk/qn3;

    invoke-static {v1, v0}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qn3;

    new-instance v1, Llyiahf/vczjk/sn3;

    check-cast v0, Llyiahf/vczjk/sv1;

    invoke-virtual {v0}, Llyiahf/vczjk/sv1;->OooO00o()Llyiahf/vczjk/lp4;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/era;

    iget-object v4, v0, Llyiahf/vczjk/sv1;->OooO00o:Llyiahf/vczjk/wv1;

    iget-object v0, v0, Llyiahf/vczjk/sv1;->OooO0O0:Llyiahf/vczjk/uv1;

    invoke-direct {v3, v4, v0}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-direct {v1, v2, p0, v3}, Llyiahf/vczjk/sn3;-><init>(Llyiahf/vczjk/lp4;Llyiahf/vczjk/hha;Llyiahf/vczjk/era;)V

    goto :goto_1

    :cond_0
    check-cast v0, Landroid/content/ContextWrapper;

    invoke-virtual {v0}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    move-result-object v0

    const-string v1, "ctx.baseContext"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v1, "Expected an activity context for creating a HiltViewModelFactory but instead found: "

    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    const/4 v1, 0x0

    :goto_1
    const/4 p0, 0x0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v1
.end method

.method public static OooOo0o(II)I
    .locals 4

    sget-object v0, Ljava/math/RoundingMode;->CEILING:Ljava/math/RoundingMode;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz p1, :cond_4

    div-int v1, p0, p1

    mul-int v2, p1, v1

    sub-int v2, p0, v2

    if-nez v2, :cond_0

    goto :goto_1

    :cond_0
    xor-int/2addr p0, p1

    shr-int/lit8 p0, p0, 0x1f

    or-int/lit8 p0, p0, 0x1

    sget-object v3, Llyiahf/vczjk/q14;->OooO00o:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v3, v0

    packed-switch v0, :pswitch_data_0

    new-instance p0, Ljava/lang/AssertionError;

    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    throw p0

    :pswitch_0
    invoke-static {v2}, Ljava/lang/Math;->abs(I)I

    move-result v0

    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    move-result p1

    sub-int/2addr p1, v0

    sub-int/2addr v0, p1

    if-nez v0, :cond_1

    sget-object p0, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    sget-object p0, Ljava/math/RoundingMode;->HALF_EVEN:Ljava/math/RoundingMode;

    goto :goto_1

    :cond_1
    if-lez v0, :cond_2

    goto :goto_0

    :pswitch_1
    if-lez p0, :cond_2

    goto :goto_0

    :pswitch_2
    if-gez p0, :cond_2

    :goto_0
    :pswitch_3
    add-int/2addr v1, p0

    return v1

    :pswitch_4
    if-nez v2, :cond_3

    :cond_2
    :goto_1
    :pswitch_5
    return v1

    :cond_3
    new-instance p0, Ljava/lang/ArithmeticException;

    const-string p1, "mode was UNNECESSARY, but rounding was necessary"

    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_4
    new-instance p0, Ljava/lang/ArithmeticException;

    const-string p1, "/ by zero"

    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw p0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_5
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static OooOoO(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;
    .locals 2

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/un;

    invoke-interface {v1}, Llyiahf/vczjk/un;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    check-cast v0, Llyiahf/vczjk/un;

    return-object v0
.end method

.method public static OooOoO0(Llyiahf/vczjk/dv1;)[Llyiahf/vczjk/sz;
    .locals 3

    invoke-virtual {p0}, Landroidx/appcompat/widget/AppCompatTextView;->getText()Ljava/lang/CharSequence;

    move-result-object p0

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    if-eqz v1, :cond_2

    instance-of v2, p0, Landroid/text/Spanned;

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    check-cast p0, Landroid/text/Spanned;

    const-class v2, Llyiahf/vczjk/sz;

    invoke-interface {p0, v0, v1, v2}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p0

    check-cast p0, [Llyiahf/vczjk/sz;

    return-object p0

    :cond_2
    :goto_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOoOO(I)Llyiahf/vczjk/kp0;
    .locals 18

    move/from16 v0, p0

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    sget-object v4, Llyiahf/vczjk/wd3;->OooOO0O:Llyiahf/vczjk/wd3;

    shr-int/lit8 v5, v0, 0x10

    and-int/lit16 v5, v5, 0xff

    invoke-static {v5}, Llyiahf/vczjk/c6a;->Oooooo(I)F

    move-result v5

    shr-int/lit8 v6, v0, 0x8

    and-int/lit16 v6, v6, 0xff

    invoke-static {v6}, Llyiahf/vczjk/c6a;->Oooooo(I)F

    move-result v6

    and-int/lit16 v0, v0, 0xff

    invoke-static {v0}, Llyiahf/vczjk/c6a;->Oooooo(I)F

    move-result v0

    sget-object v7, Llyiahf/vczjk/c6a;->OooOo00:[[D

    float-to-double v8, v5

    aget-object v5, v7, v3

    aget-wide v10, v5, v3

    mul-double/2addr v10, v8

    float-to-double v12, v6

    aget-wide v14, v5, v2

    mul-double/2addr v14, v12

    add-double/2addr v14, v10

    float-to-double v10, v0

    aget-wide v16, v5, v1

    mul-double v16, v16, v10

    add-double v5, v16, v14

    aget-object v0, v7, v2

    aget-wide v14, v0, v3

    mul-double/2addr v14, v8

    aget-wide v16, v0, v2

    mul-double v16, v16, v12

    add-double v16, v16, v14

    aget-wide v14, v0, v1

    mul-double/2addr v14, v10

    add-double v14, v14, v16

    aget-object v0, v7, v1

    aget-wide v16, v0, v3

    mul-double v8, v8, v16

    aget-wide v16, v0, v2

    mul-double v12, v12, v16

    add-double/2addr v12, v8

    aget-wide v7, v0, v1

    mul-double/2addr v10, v7

    add-double/2addr v10, v12

    double-to-float v0, v5

    double-to-float v5, v14

    double-to-float v6, v10

    const/4 v7, 0x3

    new-array v7, v7, [F

    aput v0, v7, v3

    aput v5, v7, v2

    aput v6, v7, v1

    sget-object v0, Llyiahf/vczjk/c6a;->OooOOo0:[[F

    aget v5, v7, v3

    aget-object v6, v0, v3

    aget v8, v6, v3

    mul-float/2addr v8, v5

    aget v9, v7, v2

    aget v10, v6, v2

    mul-float/2addr v10, v9

    add-float/2addr v10, v8

    aget v7, v7, v1

    aget v6, v6, v1

    mul-float/2addr v6, v7

    add-float/2addr v6, v10

    aget-object v8, v0, v2

    aget v10, v8, v3

    mul-float/2addr v10, v5

    aget v11, v8, v2

    mul-float/2addr v11, v9

    add-float/2addr v11, v10

    aget v8, v8, v1

    mul-float/2addr v8, v7

    add-float/2addr v8, v11

    aget-object v0, v0, v1

    aget v10, v0, v3

    mul-float/2addr v5, v10

    aget v10, v0, v2

    mul-float/2addr v9, v10

    add-float/2addr v9, v5

    aget v0, v0, v1

    mul-float/2addr v7, v0

    add-float/2addr v7, v9

    iget-object v0, v4, Llyiahf/vczjk/wd3;->OooO0oO:[F

    aget v3, v0, v3

    mul-float/2addr v3, v6

    aget v2, v0, v2

    mul-float/2addr v2, v8

    aget v0, v0, v1

    mul-float/2addr v0, v7

    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v1

    iget v5, v4, Llyiahf/vczjk/wd3;->OooO0oo:F

    mul-float/2addr v1, v5

    const/high16 v6, 0x42c80000    # 100.0f

    div-float/2addr v1, v6

    float-to-double v7, v1

    const v1, 0x3ed70a3d    # 0.42f

    float-to-double v9, v1

    invoke-static {v7, v8, v9, v10}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v7

    double-to-float v1, v7

    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v7

    mul-float/2addr v7, v5

    div-float/2addr v7, v6

    float-to-double v7, v7

    invoke-static {v7, v8, v9, v10}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v7

    double-to-float v7, v7

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v8

    mul-float/2addr v8, v5

    div-float/2addr v8, v6

    float-to-double v11, v8

    invoke-static {v11, v12, v9, v10}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v8

    double-to-float v5, v8

    invoke-static {v3}, Ljava/lang/Math;->signum(F)F

    move-result v3

    const/high16 v8, 0x43c80000    # 400.0f

    mul-float/2addr v3, v8

    mul-float/2addr v3, v1

    const v9, 0x41d90a3d    # 27.13f

    add-float/2addr v1, v9

    div-float/2addr v3, v1

    invoke-static {v2}, Ljava/lang/Math;->signum(F)F

    move-result v1

    mul-float/2addr v1, v8

    mul-float/2addr v1, v7

    add-float/2addr v7, v9

    div-float/2addr v1, v7

    invoke-static {v0}, Ljava/lang/Math;->signum(F)F

    move-result v0

    mul-float/2addr v0, v8

    mul-float/2addr v0, v5

    add-float/2addr v5, v9

    div-float/2addr v0, v5

    const/high16 v2, 0x41300000    # 11.0f

    mul-float v5, v3, v2

    const/high16 v7, -0x3ec00000    # -12.0f

    mul-float/2addr v7, v1

    add-float/2addr v7, v5

    add-float/2addr v7, v0

    div-float/2addr v7, v2

    add-float v2, v3, v1

    const/high16 v5, 0x40000000    # 2.0f

    mul-float v8, v0, v5

    sub-float/2addr v2, v8

    const/high16 v8, 0x41100000    # 9.0f

    div-float/2addr v2, v8

    const/high16 v8, 0x41a00000    # 20.0f

    mul-float v9, v3, v8

    mul-float/2addr v1, v8

    add-float/2addr v9, v1

    const/high16 v10, 0x41a80000    # 21.0f

    mul-float/2addr v10, v0

    add-float/2addr v10, v9

    div-float/2addr v10, v8

    const/high16 v9, 0x42200000    # 40.0f

    mul-float/2addr v3, v9

    add-float/2addr v3, v1

    add-float/2addr v3, v0

    div-float/2addr v3, v8

    float-to-double v0, v2

    float-to-double v8, v7

    invoke-static {v0, v1, v8, v9}, Ljava/lang/Math;->atan2(DD)D

    move-result-wide v0

    double-to-float v0, v0

    const/high16 v1, 0x43340000    # 180.0f

    mul-float/2addr v0, v1

    const v8, 0x40490fdb    # (float)Math.PI

    div-float/2addr v0, v8

    const/4 v9, 0x0

    cmpg-float v9, v0, v9

    const/high16 v11, 0x43b40000    # 360.0f

    if-gez v9, :cond_1

    add-float/2addr v0, v11

    :cond_0
    :goto_0
    move v12, v0

    goto :goto_1

    :cond_1
    cmpl-float v9, v0, v11

    if-ltz v9, :cond_0

    sub-float/2addr v0, v11

    goto :goto_0

    :goto_1
    mul-float v0, v12, v8

    div-float/2addr v0, v1

    iget v9, v4, Llyiahf/vczjk/wd3;->OooO0OO:F

    mul-float/2addr v3, v9

    iget v9, v4, Llyiahf/vczjk/wd3;->OooO0O0:F

    div-float/2addr v3, v9

    float-to-double v13, v3

    iget v3, v4, Llyiahf/vczjk/wd3;->OooO0o0:F

    iget v11, v4, Llyiahf/vczjk/wd3;->OooOO0:F

    mul-float/2addr v11, v3

    move v15, v1

    move/from16 p0, v2

    float-to-double v1, v11

    invoke-static {v13, v14, v1, v2}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v1

    double-to-float v1, v1

    mul-float v14, v1, v6

    float-to-double v1, v12

    const-wide v16, 0x403423d70a3d70a4L    # 20.14

    cmpg-double v1, v1, v16

    if-gez v1, :cond_2

    const/16 v1, 0x168

    int-to-float v1, v1

    add-float/2addr v1, v12

    goto :goto_2

    :cond_2
    move v1, v12

    :goto_2
    mul-float/2addr v1, v8

    div-float/2addr v1, v15

    add-float/2addr v1, v5

    float-to-double v1, v1

    invoke-static {v1, v2}, Ljava/lang/Math;->cos(D)D

    move-result-wide v1

    double-to-float v1, v1

    const v2, 0x40733333    # 3.8f

    add-float/2addr v1, v2

    const/high16 v2, 0x3e800000    # 0.25f

    mul-float/2addr v1, v2

    const v2, 0x45706276

    mul-float/2addr v1, v2

    iget v2, v4, Llyiahf/vczjk/wd3;->OooO0o:F

    mul-float/2addr v1, v2

    iget v2, v4, Llyiahf/vczjk/wd3;->OooO0Oo:F

    mul-float/2addr v1, v2

    mul-float/2addr v7, v7

    mul-float v2, p0, p0

    add-float/2addr v2, v7

    float-to-double v7, v2

    invoke-static {v7, v8}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v7

    double-to-float v2, v7

    mul-float/2addr v1, v2

    const v2, 0x3e9c28f6    # 0.305f

    add-float/2addr v10, v2

    div-float/2addr v1, v10

    float-to-double v1, v1

    const v5, 0x3f666666    # 0.9f

    float-to-double v7, v5

    invoke-static {v1, v2, v7, v8}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v1

    double-to-float v1, v1

    const v2, 0x3e947ae1    # 0.29f

    float-to-double v7, v2

    iget v2, v4, Llyiahf/vczjk/wd3;->OooO00o:F

    float-to-double v10, v2

    invoke-static {v7, v8, v10, v11}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v7

    double-to-float v2, v7

    const v5, 0x3fd1eb85    # 1.64f

    sub-float/2addr v5, v2

    float-to-double v7, v5

    const v2, 0x3f3ae148    # 0.73f

    float-to-double v10, v2

    invoke-static {v7, v8, v10, v11}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v7

    double-to-float v2, v7

    mul-float/2addr v1, v2

    div-float v2, v14, v6

    float-to-double v5, v2

    invoke-static {v5, v6}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v5

    double-to-float v2, v5

    mul-float v13, v1, v2

    iget v2, v4, Llyiahf/vczjk/wd3;->OooO:F

    mul-float/2addr v2, v13

    mul-float/2addr v1, v3

    const/high16 v3, 0x40800000    # 4.0f

    add-float/2addr v9, v3

    div-float/2addr v1, v9

    float-to-double v3, v1

    invoke-static {v3, v4}, Ljava/lang/Math;->sqrt(D)D

    const v1, 0x3fd9999a    # 1.7f

    mul-float/2addr v1, v14

    const v3, 0x3be56042    # 0.007f

    mul-float/2addr v3, v14

    const/high16 v4, 0x3f800000    # 1.0f

    add-float/2addr v3, v4

    div-float v15, v1, v3

    const v1, 0x3cbac711    # 0.0228f

    mul-float/2addr v2, v1

    add-float/2addr v2, v4

    float-to-double v1, v2

    invoke-static {v1, v2}, Ljava/lang/Math;->log(D)D

    move-result-wide v1

    double-to-float v1, v1

    const v2, 0x422f7048

    mul-float/2addr v1, v2

    float-to-double v2, v0

    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    move-result-wide v4

    double-to-float v0, v4

    mul-float v16, v1, v0

    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    move-result-wide v2

    double-to-float v0, v2

    mul-float v17, v1, v0

    new-instance v11, Llyiahf/vczjk/kp0;

    invoke-direct/range {v11 .. v17}, Llyiahf/vczjk/kp0;-><init>(FFFFFF)V

    return-object v11
.end method

.method public static OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/lg3;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/mg3;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/mg3;

    invoke-interface {p1}, Llyiahf/vczjk/mg3;->OooO0O0()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Given component holder "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " does not implement "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-class p1, Llyiahf/vczjk/lg3;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " or "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-class p1, Llyiahf/vczjk/mg3;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOoo0(FFF)Llyiahf/vczjk/kp0;
    .locals 11

    sget-object v0, Llyiahf/vczjk/wd3;->OooOO0O:Llyiahf/vczjk/wd3;

    iget v1, v0, Llyiahf/vczjk/wd3;->OooO:F

    mul-float/2addr v1, p1

    float-to-double v2, p0

    const-wide/high16 v4, 0x4059000000000000L    # 100.0

    div-double/2addr v2, v4

    invoke-static {v2, v3}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v2

    double-to-float v2, v2

    div-float v2, p1, v2

    iget v3, v0, Llyiahf/vczjk/wd3;->OooO0o0:F

    mul-float/2addr v2, v3

    const/high16 v3, 0x40800000    # 4.0f

    iget v0, v0, Llyiahf/vczjk/wd3;->OooO0O0:F

    add-float/2addr v0, v3

    div-float/2addr v2, v0

    float-to-double v2, v2

    invoke-static {v2, v3}, Ljava/lang/Math;->sqrt(D)D

    const v0, 0x40490fdb    # (float)Math.PI

    mul-float/2addr v0, p2

    const/high16 v2, 0x43340000    # 180.0f

    div-float/2addr v0, v2

    const v2, 0x3fd9999a    # 1.7f

    mul-float/2addr v2, p0

    const v3, 0x3be56042    # 0.007f

    mul-float/2addr v3, p0

    const/high16 v4, 0x3f800000    # 1.0f

    add-float/2addr v3, v4

    div-float v8, v2, v3

    const-wide v2, 0x3f9758e219652bd4L    # 0.0228

    float-to-double v4, v1

    mul-double/2addr v4, v2

    const-wide/high16 v1, 0x3ff0000000000000L    # 1.0

    add-double/2addr v4, v1

    invoke-static {v4, v5}, Ljava/lang/Math;->log(D)D

    move-result-wide v1

    double-to-float v1, v1

    const v2, 0x422f7048

    mul-float/2addr v1, v2

    float-to-double v2, v0

    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    move-result-wide v4

    double-to-float v0, v4

    mul-float v9, v1, v0

    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    move-result-wide v2

    double-to-float v0, v2

    mul-float v10, v1, v0

    new-instance v4, Llyiahf/vczjk/kp0;

    move v7, p0

    move v6, p1

    move v5, p2

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/kp0;-><init>(FFFFFF)V

    return-object v4
.end method

.method public static OooOooO([II)Z
    .locals 2

    shr-int/lit8 v0, p1, 0x5

    and-int/lit8 p1, p1, 0x1f

    const/4 v1, 0x1

    shl-int p1, v1, p1

    aget p0, p0, v0

    and-int/2addr p0, p1

    if-eqz p0, :cond_0

    return v1

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOooo(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/hha;)Llyiahf/vczjk/sn3;
    .locals 3

    const-class v0, Llyiahf/vczjk/s42;

    invoke-static {v0, p0}, Llyiahf/vczjk/mc4;->OooOoo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/s42;

    check-cast p0, Llyiahf/vczjk/sv1;

    invoke-virtual {p0}, Llyiahf/vczjk/sv1;->OooO00o()Llyiahf/vczjk/lp4;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/era;

    iget-object v2, p0, Llyiahf/vczjk/sv1;->OooO00o:Llyiahf/vczjk/wv1;

    iget-object p0, p0, Llyiahf/vczjk/sv1;->OooO0O0:Llyiahf/vczjk/uv1;

    invoke-direct {v1, v2, p0}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    new-instance p0, Llyiahf/vczjk/sn3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-direct {p0, v0, p1, v1}, Llyiahf/vczjk/sn3;-><init>(Llyiahf/vczjk/lp4;Llyiahf/vczjk/hha;Llyiahf/vczjk/era;)V

    return-object p0
.end method

.method public static final Oooo0(Llyiahf/vczjk/tf4;)Llyiahf/vczjk/gf4;
    .locals 5

    instance-of v0, p0, Llyiahf/vczjk/gf4;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/gf4;

    return-object p0

    :cond_0
    instance-of v0, p0, Llyiahf/vczjk/ei4;

    if-eqz v0, :cond_6

    check-cast p0, Llyiahf/vczjk/ei4;

    check-cast p0, Llyiahf/vczjk/fi4;

    sget-object v0, Llyiahf/vczjk/fi4;->OooOOOo:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object p0, p0, Llyiahf/vczjk/fi4;->OooOOO:Llyiahf/vczjk/wm7;

    invoke-virtual {p0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object p0

    const-string v0, "getValue(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Ljava/util/List;

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/bi4;

    const-string v4, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KTypeImpl"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Llyiahf/vczjk/di4;

    iget-object v3, v3, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/by0;

    if-eqz v4, :cond_2

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/by0;

    :cond_2
    if-eqz v2, :cond_1

    invoke-interface {v2}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    if-eq v3, v4, :cond_1

    invoke-interface {v2}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    if-eq v2, v3, :cond_1

    move-object v2, v1

    :cond_3
    check-cast v2, Llyiahf/vczjk/bi4;

    if-nez v2, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/bi4;

    :cond_4
    if-eqz v2, :cond_5

    invoke-static {v2}, Llyiahf/vczjk/mc4;->Oooo0O0(Llyiahf/vczjk/bi4;)Llyiahf/vczjk/gf4;

    move-result-object p0

    return-object p0

    :cond_5
    sget-object p0, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v0, Ljava/lang/Object;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p0

    return-object p0

    :cond_6
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot calculate JVM erasure for type: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static Oooo000(Landroid/content/Context;I)J
    .locals 1

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p0

    invoke-virtual {v0, p1, p0}, Landroid/content/res/Resources;->getColor(ILandroid/content/res/Resources$Theme;)I

    move-result p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide p0

    return-wide p0
.end method

.method public static Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;
    .locals 3

    if-ne p2, p1, :cond_0

    return-object p0

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Class;->isInterface()Z

    move-result p0

    if-eqz p0, :cond_3

    invoke-virtual {p1}, Ljava/lang/Class;->getInterfaces()[Ljava/lang/Class;

    move-result-object p0

    array-length v0, p0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_3

    aget-object v2, p0, v1

    if-ne v2, p2, :cond_1

    invoke-virtual {p1}, Ljava/lang/Class;->getGenericInterfaces()[Ljava/lang/reflect/Type;

    move-result-object p0

    aget-object p0, p0, v1

    return-object p0

    :cond_1
    invoke-virtual {p2, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {p1}, Ljava/lang/Class;->getGenericInterfaces()[Ljava/lang/reflect/Type;

    move-result-object p1

    aget-object p1, p1, v1

    aget-object p0, p0, v1

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/mc4;->Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    move-result-object p0

    return-object p0

    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_3
    invoke-virtual {p1}, Ljava/lang/Class;->isInterface()Z

    move-result p0

    if-nez p0, :cond_6

    :goto_1
    const-class p0, Ljava/lang/Object;

    if-eq p1, p0, :cond_6

    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p0

    if-ne p0, p2, :cond_4

    invoke-virtual {p1}, Ljava/lang/Class;->getGenericSuperclass()Ljava/lang/reflect/Type;

    move-result-object p0

    return-object p0

    :cond_4
    invoke-virtual {p2, p0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Ljava/lang/Class;->getGenericSuperclass()Ljava/lang/reflect/Type;

    move-result-object p1

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/mc4;->Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    move-result-object p0

    return-object p0

    :cond_5
    move-object p1, p0

    goto :goto_1

    :cond_6
    return-object p2
.end method

.method public static final Oooo0O0(Llyiahf/vczjk/bi4;)Llyiahf/vczjk/gf4;
    .locals 3

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/di4;

    invoke-virtual {v0}, Llyiahf/vczjk/di4;->OooO0OO()Llyiahf/vczjk/tf4;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->Oooo0(Llyiahf/vczjk/tf4;)Llyiahf/vczjk/gf4;

    move-result-object p0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot calculate JVM erasure for type: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static Oooo0OO(Ljava/lang/reflect/Type;)Ljava/lang/Class;
    .locals 4

    instance-of v0, p0, Ljava/lang/Class;

    if-eqz v0, :cond_0

    check-cast p0, Ljava/lang/Class;

    return-object p0

    :cond_0
    instance-of v0, p0, Ljava/lang/reflect/ParameterizedType;

    if-eqz v0, :cond_1

    check-cast p0, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object p0

    instance-of v0, p0, Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->OooOo00(Z)V

    check-cast p0, Ljava/lang/Class;

    return-object p0

    :cond_1
    instance-of v0, p0, Ljava/lang/reflect/GenericArrayType;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p0, Ljava/lang/reflect/GenericArrayType;

    invoke-interface {p0}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/mc4;->Oooo0OO(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    move-result-object p0

    invoke-static {p0, v1}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    return-object p0

    :cond_2
    instance-of v0, p0, Ljava/lang/reflect/TypeVariable;

    if-eqz v0, :cond_3

    const-class p0, Ljava/lang/Object;

    return-object p0

    :cond_3
    instance-of v0, p0, Ljava/lang/reflect/WildcardType;

    if-eqz v0, :cond_4

    check-cast p0, Ljava/lang/reflect/WildcardType;

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object p0

    aget-object p0, p0, v1

    invoke-static {p0}, Llyiahf/vczjk/mc4;->Oooo0OO(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    move-result-object p0

    return-object p0

    :cond_4
    if-nez p0, :cond_5

    const-string v0, "null"

    goto :goto_0

    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    :goto_0
    new-instance v1, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Expected a Class, ParameterizedType, or GenericArrayType, but <"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, "> is of type "

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public static Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;
    .locals 2

    const-string v0, "refHolder"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zd3;

    if-eqz v0, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/zd3;->OooOOO0:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {v1, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    new-instance v0, Llyiahf/vczjk/zd3;

    invoke-direct {v0, p1}, Llyiahf/vczjk/zd3;-><init>(Landroid/database/sqlite/SQLiteDatabase;)V

    iput-object v0, p0, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    return-object v0
.end method

.method public static Oooo0oo(Llyiahf/vczjk/ko;Llyiahf/vczjk/hc3;)Z
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1}, Llyiahf/vczjk/ko;->OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object p0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OoooO0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/bw5;
    .locals 9

    new-instance v0, Llyiahf/vczjk/cw5;

    invoke-direct {v0}, Llyiahf/vczjk/cw5;-><init>()V

    invoke-interface {p0, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-boolean v2, v0, Llyiahf/vczjk/cw5;->OooO0O0:Z

    iget-object p0, v0, Llyiahf/vczjk/cw5;->OooO00o:Llyiahf/vczjk/aw5;

    iget-boolean v3, v0, Llyiahf/vczjk/cw5;->OooO0OO:Z

    iget-object v1, v0, Llyiahf/vczjk/cw5;->OooO0o0:Ljava/lang/String;

    if-eqz v1, :cond_0

    iget-boolean v0, v0, Llyiahf/vczjk/cw5;->OooO0o:Z

    iput-object v1, p0, Llyiahf/vczjk/aw5;->OooO0O0:Ljava/lang/String;

    const/4 v1, -0x1

    iput v1, p0, Llyiahf/vczjk/aw5;->OooO00o:I

    iput-boolean v0, p0, Llyiahf/vczjk/aw5;->OooO0OO:Z

    goto :goto_0

    :cond_0
    iget v1, v0, Llyiahf/vczjk/cw5;->OooO0Oo:I

    iget-boolean v0, v0, Llyiahf/vczjk/cw5;->OooO0o:Z

    iput v1, p0, Llyiahf/vczjk/aw5;->OooO00o:I

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/aw5;->OooO0O0:Ljava/lang/String;

    iput-boolean v0, p0, Llyiahf/vczjk/aw5;->OooO0OO:Z

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/aw5;->OooO0O0:Ljava/lang/String;

    if-eqz v0, :cond_1

    new-instance v1, Llyiahf/vczjk/bw5;

    iget-boolean v6, p0, Llyiahf/vczjk/aw5;->OooO0OO:Z

    iget v7, p0, Llyiahf/vczjk/aw5;->OooO0Oo:I

    iget v8, p0, Llyiahf/vczjk/aw5;->OooO0o0:I

    sget p0, Llyiahf/vczjk/av5;->OooOOo0:I

    const-string p0, "android-app://androidx.navigation/"

    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    move-result v4

    const/4 v5, 0x0

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/bw5;-><init>(ZZIZZII)V

    iput-object v0, v1, Llyiahf/vczjk/bw5;->OooO0oo:Ljava/lang/String;

    return-object v1

    :cond_1
    new-instance v1, Llyiahf/vczjk/bw5;

    iget v4, p0, Llyiahf/vczjk/aw5;->OooO00o:I

    iget-boolean v6, p0, Llyiahf/vczjk/aw5;->OooO0OO:Z

    iget v7, p0, Llyiahf/vczjk/aw5;->OooO0Oo:I

    iget v8, p0, Llyiahf/vczjk/aw5;->OooO0o0:I

    const/4 v5, 0x0

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/bw5;-><init>(ZZIZZII)V

    return-object v1
.end method

.method public static OoooO00(I)I
    .locals 4

    sget-object v0, Ljava/math/RoundingMode;->UNNECESSARY:Ljava/math/RoundingMode;

    if-lez p0, :cond_3

    sget-object v1, Llyiahf/vczjk/q14;->OooO00o:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v1, v0

    const/4 v1, 0x1

    packed-switch v0, :pswitch_data_0

    new-instance p0, Ljava/lang/AssertionError;

    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    throw p0

    :pswitch_0
    invoke-static {p0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    move-result v0

    const v1, -0x4afb0ccd

    ushr-int/2addr v1, v0

    rsub-int/lit8 v0, v0, 0x1f

    sub-int/2addr v1, p0

    not-int p0, v1

    not-int p0, p0

    ushr-int/lit8 p0, p0, 0x1f

    add-int/2addr v0, p0

    return v0

    :pswitch_1
    sub-int/2addr p0, v1

    invoke-static {p0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    move-result p0

    rsub-int/lit8 p0, p0, 0x20

    return p0

    :pswitch_2
    const/4 v0, 0x0

    if-lez p0, :cond_0

    move v2, v1

    goto :goto_0

    :cond_0
    move v2, v0

    :goto_0
    add-int/lit8 v3, p0, -0x1

    and-int/2addr v3, p0

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    move v1, v0

    :goto_1
    and-int v0, v2, v1

    if-eqz v0, :cond_2

    :pswitch_3
    invoke-static {p0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    move-result p0

    rsub-int/lit8 p0, p0, 0x1f

    return p0

    :cond_2
    new-instance p0, Ljava/lang/ArithmeticException;

    const-string v0, "mode was UNNECESSARY, but rounding was necessary"

    invoke-direct {p0, v0}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "x ("

    const-string v2, ") must be > 0"

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_3
        :pswitch_3
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static OoooO0O(Landroid/content/pm/PackageInfo;Ljava/io/File;)V
    .locals 2

    new-instance v0, Ljava/io/File;

    const-string v1, "profileinstaller_profileWrittenFor_lastUpdateTime.dat"

    invoke-direct {v0, p1, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    :try_start_0
    new-instance p1, Ljava/io/DataOutputStream;

    new-instance v1, Ljava/io/FileOutputStream;

    invoke-direct {v1, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    invoke-direct {p1, v1}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    :try_start_1
    iget-wide v0, p0, Landroid/content/pm/PackageInfo;->lastUpdateTime:J

    invoke-virtual {p1, v0, v1}, Ljava/io/DataOutputStream;->writeLong(J)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-virtual {p1}, Ljava/io/OutputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    return-void

    :catchall_0
    move-exception p0

    :try_start_3
    invoke-virtual {p1}, Ljava/io/OutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p1

    :try_start_4
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_0
    throw p0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    :catch_0
    return-void
.end method

.method public static OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;
    .locals 10

    const/4 v0, 0x0

    const/4 v1, 0x1

    const/4 v2, 0x0

    move-object v3, v2

    :cond_0
    instance-of v4, p2, Ljava/lang/reflect/TypeVariable;

    if-eqz v4, :cond_9

    move-object v4, p2

    check-cast v4, Ljava/lang/reflect/TypeVariable;

    invoke-virtual {p3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/reflect/Type;

    sget-object v6, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    if-eqz v5, :cond_2

    if-ne v5, v6, :cond_1

    return-object p2

    :cond_1
    return-object v5

    :cond_2
    invoke-virtual {p3, v4, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    if-nez v3, :cond_3

    move-object v3, v4

    :cond_3
    invoke-interface {v4}, Ljava/lang/reflect/TypeVariable;->getGenericDeclaration()Ljava/lang/reflect/GenericDeclaration;

    move-result-object p2

    instance-of v5, p2, Ljava/lang/Class;

    if-eqz v5, :cond_4

    check-cast p2, Ljava/lang/Class;

    goto :goto_0

    :cond_4
    move-object p2, v2

    :goto_0
    if-nez p2, :cond_5

    goto :goto_2

    :cond_5
    invoke-static {p0, p1, p2}, Llyiahf/vczjk/mc4;->Oooo00o(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    move-result-object v5

    instance-of v6, v5, Ljava/lang/reflect/ParameterizedType;

    if-eqz v6, :cond_8

    invoke-virtual {p2}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    move-result-object p2

    array-length v6, p2

    move v7, v0

    :goto_1
    if-ge v7, v6, :cond_7

    aget-object v8, p2, v7

    invoke-virtual {v4, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    check-cast v5, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {v5}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p2

    aget-object p2, p2, v7

    goto :goto_3

    :cond_6
    add-int/2addr v7, v1

    goto :goto_1

    :cond_7
    new-instance p0, Ljava/util/NoSuchElementException;

    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    throw p0

    :cond_8
    :goto_2
    move-object p2, v4

    :goto_3
    if-ne p2, v4, :cond_0

    goto/16 :goto_8

    :cond_9
    instance-of v2, p2, Ljava/lang/Class;

    if-eqz v2, :cond_b

    move-object v2, p2

    check-cast v2, Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/Class;->isArray()Z

    move-result v4

    if-eqz v4, :cond_b

    invoke-virtual {v2}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object p2

    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-static {p2, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_a

    move-object p2, v2

    goto/16 :goto_8

    :cond_a
    new-instance p1, Llyiahf/vczjk/rk3;

    invoke-direct {p1, p0}, Llyiahf/vczjk/rk3;-><init>(Ljava/lang/reflect/Type;)V

    :goto_4
    move-object p2, p1

    goto/16 :goto_8

    :cond_b
    instance-of v2, p2, Ljava/lang/reflect/GenericArrayType;

    if-eqz v2, :cond_d

    check-cast p2, Ljava/lang/reflect/GenericArrayType;

    invoke-interface {p2}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object v0

    invoke-static {p0, p1, v0, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object p0

    invoke-static {v0, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_c

    goto/16 :goto_8

    :cond_c
    new-instance p1, Llyiahf/vczjk/rk3;

    invoke-direct {p1, p0}, Llyiahf/vczjk/rk3;-><init>(Ljava/lang/reflect/Type;)V

    goto :goto_4

    :cond_d
    instance-of v2, p2, Ljava/lang/reflect/ParameterizedType;

    if-eqz v2, :cond_12

    check-cast p2, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {p2}, Ljava/lang/reflect/ParameterizedType;->getOwnerType()Ljava/lang/reflect/Type;

    move-result-object v2

    invoke-static {p0, p1, v2, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object v4

    invoke-static {v4, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    invoke-interface {p2}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object v5

    array-length v6, v5

    move-object v7, v5

    move v5, v0

    :goto_5
    if-ge v0, v6, :cond_10

    aget-object v8, v7, v0

    invoke-static {p0, p1, v8, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object v8

    aget-object v9, v7, v0

    invoke-static {v8, v9}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_f

    if-nez v5, :cond_e

    invoke-virtual {v7}, [Ljava/lang/reflect/Type;->clone()Ljava/lang/Object;

    move-result-object v5

    move-object v7, v5

    check-cast v7, [Ljava/lang/reflect/Type;

    move v5, v1

    :cond_e
    aput-object v8, v7, v0

    :cond_f
    add-int/2addr v0, v1

    goto :goto_5

    :cond_10
    if-eqz v2, :cond_11

    if-eqz v5, :cond_16

    :cond_11
    invoke-interface {p2}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object p0

    check-cast p0, Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/sk3;

    invoke-direct {p1, v4, p0, v7}, Llyiahf/vczjk/sk3;-><init>(Ljava/lang/reflect/Type;Ljava/lang/Class;[Ljava/lang/reflect/Type;)V

    goto :goto_4

    :cond_12
    instance-of v2, p2, Ljava/lang/reflect/WildcardType;

    if-eqz v2, :cond_16

    check-cast p2, Ljava/lang/reflect/WildcardType;

    invoke-interface {p2}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object v2

    invoke-interface {p2}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object v4

    array-length v5, v2

    if-ne v5, v1, :cond_14

    aget-object v4, v2, v0

    invoke-static {p0, p1, v4, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object p0

    aget-object p1, v2, v0

    if-eq p0, p1, :cond_16

    instance-of p1, p0, Ljava/lang/reflect/WildcardType;

    if-eqz p1, :cond_13

    check-cast p0, Ljava/lang/reflect/WildcardType;

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object p0

    goto :goto_6

    :cond_13
    new-array p1, v1, [Ljava/lang/reflect/Type;

    aput-object p0, p1, v0

    move-object p0, p1

    :goto_6
    new-instance p2, Llyiahf/vczjk/tk3;

    new-array p1, v1, [Ljava/lang/reflect/Type;

    const-class v1, Ljava/lang/Object;

    aput-object v1, p1, v0

    invoke-direct {p2, p1, p0}, Llyiahf/vczjk/tk3;-><init>([Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V

    goto :goto_8

    :cond_14
    array-length v2, v4

    if-ne v2, v1, :cond_16

    aget-object v2, v4, v0

    invoke-static {p0, p1, v2, p3}, Llyiahf/vczjk/mc4;->OoooOOo(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    move-result-object p0

    aget-object p1, v4, v0

    if-eq p0, p1, :cond_16

    instance-of p1, p0, Ljava/lang/reflect/WildcardType;

    if-eqz p1, :cond_15

    check-cast p0, Ljava/lang/reflect/WildcardType;

    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object p0

    goto :goto_7

    :cond_15
    new-array p1, v1, [Ljava/lang/reflect/Type;

    aput-object p0, p1, v0

    move-object p0, p1

    :goto_7
    new-instance p2, Llyiahf/vczjk/tk3;

    sget-object p1, Llyiahf/vczjk/mc4;->OooOo0:[Ljava/lang/reflect/Type;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/tk3;-><init>([Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V

    :cond_16
    :goto_8
    if-eqz v3, :cond_17

    invoke-virtual {p3, v3, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_17
    return-object p2
.end method

.method public static OoooOo0(ILjava/lang/CharSequence;)I
    .locals 7

    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const/4 v1, -0x1

    if-lt p0, v0, :cond_0

    return v1

    :cond_0
    invoke-interface {p1, p0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    const/16 v2, 0x5c

    const/16 v3, 0x3c

    if-ne v0, v3, :cond_5

    :cond_1
    :goto_0
    add-int/lit8 p0, p0, 0x1

    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    if-ge p0, v0, :cond_4

    invoke-interface {p1, p0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    const/16 v4, 0xa

    if-eq v0, v4, :cond_4

    if-eq v0, v3, :cond_4

    const/16 v4, 0x3e

    if-eq v0, v4, :cond_3

    if-eq v0, v2, :cond_2

    goto :goto_0

    :cond_2
    add-int/lit8 v0, p0, 0x1

    invoke-static {v0, p1}, Llyiahf/vczjk/tp6;->OooOoo(ILjava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_1

    move p0, v0

    goto :goto_0

    :cond_3
    add-int/lit8 p0, p0, 0x1

    return p0

    :cond_4
    return v1

    :cond_5
    const/4 v0, 0x0

    move v3, p0

    :goto_1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v4

    if-ge v3, v4, :cond_d

    invoke-interface {p1, v3}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v4

    if-eqz v4, :cond_b

    const/16 v5, 0x20

    if-eq v4, v5, :cond_b

    if-eq v4, v2, :cond_9

    const/16 v6, 0x28

    if-eq v4, v6, :cond_8

    const/16 v5, 0x29

    if-eq v4, v5, :cond_6

    invoke-static {v4}, Ljava/lang/Character;->isISOControl(C)Z

    move-result v4

    if-eqz v4, :cond_a

    if-eq v3, p0, :cond_c

    goto :goto_3

    :cond_6
    if-nez v0, :cond_7

    goto :goto_3

    :cond_7
    add-int/lit8 v0, v0, -0x1

    goto :goto_2

    :cond_8
    add-int/lit8 v0, v0, 0x1

    if-le v0, v5, :cond_a

    goto :goto_4

    :cond_9
    add-int/lit8 v4, v3, 0x1

    invoke-static {v4, p1}, Llyiahf/vczjk/tp6;->OooOoo(ILjava/lang/CharSequence;)Z

    move-result v5

    if-eqz v5, :cond_a

    move v3, v4

    :cond_a
    :goto_2
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_b
    if-eq v3, p0, :cond_c

    :goto_3
    return v3

    :cond_c
    :goto_4
    return v1

    :cond_d
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result p0

    return p0
.end method

.method public static OoooOoO(ILjava/lang/CharSequence;)I
    .locals 2

    :goto_0
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    if-ge p0, v0, :cond_1

    invoke-interface {p1, p0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    packed-switch v0, :pswitch_data_0

    goto :goto_1

    :pswitch_0
    return p0

    :pswitch_1
    add-int/lit8 v0, p0, 0x1

    invoke-static {v0, p1}, Llyiahf/vczjk/tp6;->OooOoo(ILjava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    move p0, v0

    :cond_0
    :goto_1
    add-int/lit8 p0, p0, 0x1

    goto :goto_0

    :pswitch_2
    const/4 p0, -0x1

    return p0

    :cond_1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result p0

    return p0

    :pswitch_data_0
    .packed-switch 0x5b
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static OoooOoo(Ljava/lang/CharSequence;IC)I
    .locals 3

    :goto_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result v0

    if-ge p1, v0, :cond_3

    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    const/16 v1, 0x5c

    if-ne v0, v1, :cond_0

    add-int/lit8 v1, p1, 0x1

    invoke-static {v1, p0}, Llyiahf/vczjk/tp6;->OooOoo(ILjava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_0

    move p1, v1

    goto :goto_1

    :cond_0
    if-ne v0, p2, :cond_1

    return p1

    :cond_1
    const/16 v1, 0x29

    if-ne p2, v1, :cond_2

    const/16 v1, 0x28

    if-ne v0, v1, :cond_2

    const/4 p0, -0x1

    return p0

    :cond_2
    :goto_1
    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_3
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result p0

    return p0
.end method

.method public static final Ooooo0o(Ljava/util/List;)Ljava/util/ArrayList;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const-wide/16 v1, 0x0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/iu0;

    iget-wide v3, v3, Llyiahf/vczjk/iu0;->OooO0OO:J

    add-long/2addr v1, v3

    goto :goto_0

    :cond_0
    long-to-float v0, v1

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {p0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/iu0;

    new-instance v3, Llyiahf/vczjk/ju0;

    iget-wide v4, v2, Llyiahf/vczjk/iu0;->OooO0OO:J

    long-to-float v4, v4

    div-float/2addr v4, v0

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/ju0;-><init>(Llyiahf/vczjk/iu0;F)V

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    return-object v1
.end method

.method public static OooooO0(Ljava/lang/reflect/Type;)Ljava/lang/String;
    .locals 1

    instance-of v0, p0, Ljava/lang/Class;

    if-eqz v0, :cond_0

    check-cast p0, Ljava/lang/Class;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooooOO(Llyiahf/vczjk/dv1;)V
    .locals 4

    sget v0, Lio/noties/markwon/R$id;->markwon_drawables_scheduler_last_text_hashcode:I

    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    sget v0, Lio/noties/markwon/R$id;->markwon_drawables_scheduler_last_text_hashcode:I

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    invoke-static {p0}, Llyiahf/vczjk/mc4;->OooOoO0(Llyiahf/vczjk/dv1;)[Llyiahf/vczjk/sz;

    move-result-object p0

    if-eqz p0, :cond_1

    array-length v0, p0

    if-lez v0, :cond_1

    array-length v0, p0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    aget-object v3, p0, v2

    iget-object v3, v3, Llyiahf/vczjk/sz;->OooOOO:Llyiahf/vczjk/oz;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/oz;->OooO0OO(Landroid/graphics/drawable/Drawable$Callback;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method

.method public static OooooOo(Landroid/content/Context;Ljava/util/concurrent/Executor;Llyiahf/vczjk/i87;Z)V
    .locals 18

    move-object/from16 v1, p0

    move-object/from16 v5, p2

    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object v3

    invoke-virtual {v0}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v4

    new-instance v0, Ljava/io/File;

    iget-object v3, v3, Landroid/content/pm/ApplicationInfo;->sourceDir:Ljava/lang/String;

    invoke-direct {v0, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    const/4 v8, 0x7

    const/4 v9, 0x0

    :try_start_0
    invoke-virtual {v0, v2, v9}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object v10
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_12

    invoke-virtual {v1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object v11

    const-string v3, "ProfileInstaller"

    const/4 v12, 0x0

    if-nez p3, :cond_4

    new-instance v0, Ljava/io/File;

    const-string v7, "profileinstaller_profileWrittenFor_lastUpdateTime.dat"

    invoke-direct {v0, v11, v7}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v7

    if-nez v7, :cond_0

    :catch_0
    move v0, v9

    goto :goto_2

    :cond_0
    :try_start_1
    new-instance v7, Ljava/io/DataInputStream;

    new-instance v14, Ljava/io/FileInputStream;

    invoke-direct {v14, v0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    invoke-direct {v7, v14}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    :try_start_2
    invoke-virtual {v7}, Ljava/io/DataInputStream;->readLong()J

    move-result-wide v14
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :try_start_3
    invoke-virtual {v7}, Ljava/io/InputStream;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0

    move-wide/from16 v16, v14

    iget-wide v13, v10, Landroid/content/pm/PackageInfo;->lastUpdateTime:J

    cmp-long v0, v16, v13

    if-nez v0, :cond_1

    const/4 v0, 0x1

    goto :goto_0

    :cond_1
    move v0, v9

    :goto_0
    if-eqz v0, :cond_2

    const/4 v7, 0x2

    invoke-interface {v5, v7, v12}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_2

    :catchall_0
    move-exception v0

    move-object v13, v0

    :try_start_4
    invoke-virtual {v7}, Ljava/io/InputStream;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    goto :goto_1

    :catchall_1
    move-exception v0

    :try_start_5
    invoke-virtual {v13, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1
    throw v13
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0

    :cond_2
    :goto_2
    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Skipping profile installation for "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    invoke-static {v1, v9}, Llyiahf/vczjk/n97;->OooO0OO(Landroid/content/Context;Z)V

    goto/16 :goto_38

    :cond_4
    :goto_3
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v7, "Installing profile for "

    invoke-direct {v0, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v3, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    new-instance v7, Ljava/io/File;

    new-instance v0, Ljava/io/File;

    const-string v3, "/data/misc/profiles/cur/0"

    invoke-direct {v0, v3, v2}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    const-string v2, "primary.prof"

    invoke-direct {v7, v0, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/n92;

    const-string v0, "dexopt/baseline.prof"

    move-object v3, v4

    move-object/from16 v4, p1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/n92;-><init>(Landroid/content/res/AssetManager;Ljava/util/concurrent/Executor;Llyiahf/vczjk/i87;Ljava/lang/String;Ljava/io/File;)V

    iget-object v4, v2, Llyiahf/vczjk/n92;->OooO0OO:[B

    if-nez v4, :cond_5

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    const/4 v3, 0x3

    invoke-virtual {v2, v3, v0}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V

    :goto_4
    const/4 v7, 0x1

    goto/16 :goto_35

    :cond_5
    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    move-result v6

    const/4 v13, 0x4

    if-eqz v6, :cond_7

    invoke-virtual {v7}, Ljava/io/File;->canWrite()Z

    move-result v6

    if-nez v6, :cond_6

    invoke-virtual {v2, v13, v12}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V

    goto :goto_4

    :cond_6
    const/4 v6, 0x1

    goto :goto_5

    :cond_7
    :try_start_6
    invoke-virtual {v7}, Ljava/io/File;->createNewFile()Z

    move-result v6

    if-nez v6, :cond_6

    invoke-virtual {v2, v13, v12}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1

    goto :goto_4

    :catch_1
    const/4 v7, 0x1

    goto/16 :goto_34

    :goto_5
    iput-boolean v6, v2, Llyiahf/vczjk/n92;->OooO0o:Z

    sget-object v6, Llyiahf/vczjk/yi4;->OooO0o:[B

    const/4 v7, 0x6

    :try_start_7
    invoke-virtual {v2, v3, v0}, Llyiahf/vczjk/n92;->OooO00o(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/FileInputStream;

    move-result-object v0
    :try_end_7
    .catch Ljava/io/FileNotFoundException; {:try_start_7 .. :try_end_7} :catch_3
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_2

    move-object v14, v0

    goto :goto_7

    :catch_2
    move-exception v0

    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_6

    :catch_3
    move-exception v0

    invoke-interface {v5, v7, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    :goto_6
    move-object v14, v12

    :goto_7
    const-string v15, "Invalid magic"

    const/16 v7, 0x8

    if-eqz v14, :cond_9

    :try_start_8
    invoke-static {v14, v13}, Llyiahf/vczjk/u34;->OoooOO0(Ljava/io/InputStream;I)[B

    move-result-object v0

    invoke-static {v6, v0}, Ljava/util/Arrays;->equals([B[B)Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-static {v14, v13}, Llyiahf/vczjk/u34;->OoooOO0(Ljava/io/InputStream;I)[B

    move-result-object v0

    iget-object v9, v2, Llyiahf/vczjk/n92;->OooO0o0:Ljava/lang/String;

    invoke-static {v14, v0, v9}, Llyiahf/vczjk/yi4;->o00Oo0(Ljava/io/FileInputStream;[BLjava/lang/String;)[Llyiahf/vczjk/y92;

    move-result-object v9
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_6
    .catch Ljava/lang/IllegalStateException; {:try_start_8 .. :try_end_8} :catch_5
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    :try_start_9
    invoke-virtual {v14}, Ljava/io/InputStream;->close()V
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_4

    goto :goto_c

    :catch_4
    move-exception v0

    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_c

    :goto_8
    move-object v1, v0

    goto :goto_d

    :catchall_2
    move-exception v0

    goto :goto_8

    :catch_5
    move-exception v0

    goto :goto_9

    :catch_6
    move-exception v0

    goto :goto_a

    :cond_8
    :try_start_a
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_6
    .catch Ljava/lang/IllegalStateException; {:try_start_a .. :try_end_a} :catch_5
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    :goto_9
    :try_start_b
    invoke-interface {v5, v7, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    :try_start_c
    invoke-virtual {v14}, Ljava/io/InputStream;->close()V
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_7

    goto :goto_b

    :catch_7
    move-exception v0

    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_b

    :goto_a
    :try_start_d
    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_2

    :try_start_e
    invoke-virtual {v14}, Ljava/io/InputStream;->close()V
    :try_end_e
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_7

    :goto_b
    move-object v9, v12

    :goto_c
    iput-object v9, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    goto :goto_f

    :goto_d
    :try_start_f
    invoke-virtual {v14}, Ljava/io/InputStream;->close()V
    :try_end_f
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_8

    goto :goto_e

    :catch_8
    move-exception v0

    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    :goto_e
    throw v1

    :cond_9
    :goto_f
    iget-object v0, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    if-eqz v0, :cond_f

    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v14, 0x1f

    if-lt v9, v14, :cond_a

    goto :goto_10

    :cond_a
    const/16 v14, 0x18

    if-eq v9, v14, :cond_b

    const/16 v14, 0x19

    if-eq v9, v14, :cond_b

    goto :goto_18

    :cond_b
    :goto_10
    :try_start_10
    const-string v9, "dexopt/baseline.profm"

    invoke-virtual {v2, v3, v9}, Llyiahf/vczjk/n92;->OooO00o(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/FileInputStream;

    move-result-object v3
    :try_end_10
    .catch Ljava/io/FileNotFoundException; {:try_start_10 .. :try_end_10} :catch_b
    .catch Ljava/io/IOException; {:try_start_10 .. :try_end_10} :catch_a
    .catch Ljava/lang/IllegalStateException; {:try_start_10 .. :try_end_10} :catch_9

    if-eqz v3, :cond_d

    :try_start_11
    sget-object v9, Llyiahf/vczjk/yi4;->OooO0oO:[B

    invoke-static {v3, v13}, Llyiahf/vczjk/u34;->OoooOO0(Ljava/io/InputStream;I)[B

    move-result-object v14

    invoke-static {v9, v14}, Ljava/util/Arrays;->equals([B[B)Z

    move-result v9

    if-eqz v9, :cond_c

    invoke-static {v3, v13}, Llyiahf/vczjk/u34;->OoooOO0(Ljava/io/InputStream;I)[B

    move-result-object v9

    invoke-static {v3, v9, v4, v0}, Llyiahf/vczjk/yi4;->o0OoOo0(Ljava/io/FileInputStream;[B[B[Llyiahf/vczjk/y92;)[Llyiahf/vczjk/y92;

    move-result-object v0

    iput-object v0, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_3

    :try_start_12
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    :try_end_12
    .catch Ljava/io/FileNotFoundException; {:try_start_12 .. :try_end_12} :catch_b
    .catch Ljava/io/IOException; {:try_start_12 .. :try_end_12} :catch_a
    .catch Ljava/lang/IllegalStateException; {:try_start_12 .. :try_end_12} :catch_9

    move-object v0, v2

    goto :goto_17

    :catch_9
    move-exception v0

    goto :goto_13

    :catch_a
    move-exception v0

    goto :goto_14

    :catch_b
    move-exception v0

    goto :goto_15

    :catchall_3
    move-exception v0

    move-object v4, v0

    goto :goto_11

    :cond_c
    :try_start_13
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v15}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_3

    :goto_11
    :try_start_14
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_4

    goto :goto_12

    :catchall_4
    move-exception v0

    :try_start_15
    invoke-virtual {v4, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_12
    throw v4

    :cond_d
    if-eqz v3, :cond_e

    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    :try_end_15
    .catch Ljava/io/FileNotFoundException; {:try_start_15 .. :try_end_15} :catch_b
    .catch Ljava/io/IOException; {:try_start_15 .. :try_end_15} :catch_a
    .catch Ljava/lang/IllegalStateException; {:try_start_15 .. :try_end_15} :catch_9

    goto :goto_16

    :goto_13
    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    invoke-interface {v5, v7, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_16

    :goto_14
    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_16

    :goto_15
    const/16 v3, 0x9

    invoke-interface {v5, v3, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    :cond_e
    :goto_16
    move-object v0, v12

    :goto_17
    if-eqz v0, :cond_f

    move-object v2, v0

    :cond_f
    :goto_18
    iget-object v3, v2, Llyiahf/vczjk/n92;->OooO0O0:Llyiahf/vczjk/i87;

    iget-object v0, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    const-string v4, "This device doesn\'t support aot. Did you call deviceSupportsAotProfile()?"

    if-eqz v0, :cond_13

    iget-object v5, v2, Llyiahf/vczjk/n92;->OooO0OO:[B

    if-nez v5, :cond_10

    goto :goto_1e

    :cond_10
    iget-boolean v9, v2, Llyiahf/vczjk/n92;->OooO0o:Z

    if-eqz v9, :cond_12

    :try_start_16
    new-instance v9, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v9}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_16
    .catch Ljava/io/IOException; {:try_start_16 .. :try_end_16} :catch_d
    .catch Ljava/lang/IllegalStateException; {:try_start_16 .. :try_end_16} :catch_c

    :try_start_17
    invoke-virtual {v9, v6}, Ljava/io/OutputStream;->write([B)V

    invoke-virtual {v9, v5}, Ljava/io/OutputStream;->write([B)V

    invoke-static {v9, v5, v0}, Llyiahf/vczjk/yi4;->o0OO00O(Ljava/io/ByteArrayOutputStream;[B[Llyiahf/vczjk/y92;)Z

    move-result v0

    if-nez v0, :cond_11

    const/4 v0, 0x5

    invoke-interface {v3, v0, v12}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;
    :try_end_17
    .catchall {:try_start_17 .. :try_end_17} :catchall_5

    :try_start_18
    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_18
    .catch Ljava/io/IOException; {:try_start_18 .. :try_end_18} :catch_d
    .catch Ljava/lang/IllegalStateException; {:try_start_18 .. :try_end_18} :catch_c

    goto :goto_1e

    :catch_c
    move-exception v0

    goto :goto_1b

    :catch_d
    move-exception v0

    goto :goto_1c

    :catchall_5
    move-exception v0

    move-object v5, v0

    goto :goto_19

    :cond_11
    :try_start_19
    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object v0

    iput-object v0, v2, Llyiahf/vczjk/n92;->OooO0oo:[B
    :try_end_19
    .catchall {:try_start_19 .. :try_end_19} :catchall_5

    :try_start_1a
    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_1a
    .catch Ljava/io/IOException; {:try_start_1a .. :try_end_1a} :catch_d
    .catch Ljava/lang/IllegalStateException; {:try_start_1a .. :try_end_1a} :catch_c

    goto :goto_1d

    :goto_19
    :try_start_1b
    invoke-virtual {v9}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_1b
    .catchall {:try_start_1b .. :try_end_1b} :catchall_6

    goto :goto_1a

    :catchall_6
    move-exception v0

    :try_start_1c
    invoke-virtual {v5, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1a
    throw v5
    :try_end_1c
    .catch Ljava/io/IOException; {:try_start_1c .. :try_end_1c} :catch_d
    .catch Ljava/lang/IllegalStateException; {:try_start_1c .. :try_end_1c} :catch_c

    :goto_1b
    invoke-interface {v3, v7, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    goto :goto_1d

    :goto_1c
    invoke-interface {v3, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    :goto_1d
    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    goto :goto_1e

    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_13
    :goto_1e
    iget-object v0, v2, Llyiahf/vczjk/n92;->OooO0oo:[B

    if-nez v0, :cond_14

    const/4 v6, 0x0

    const/4 v7, 0x1

    goto/16 :goto_32

    :cond_14
    iget-boolean v3, v2, Llyiahf/vczjk/n92;->OooO0o:Z

    if-eqz v3, :cond_1a

    :try_start_1d
    new-instance v3, Ljava/io/ByteArrayInputStream;

    invoke-direct {v3, v0}, Ljava/io/ByteArrayInputStream;-><init>([B)V
    :try_end_1d
    .catch Ljava/io/FileNotFoundException; {:try_start_1d .. :try_end_1d} :catch_11
    .catch Ljava/io/IOException; {:try_start_1d .. :try_end_1d} :catch_10
    .catchall {:try_start_1d .. :try_end_1d} :catchall_7

    :try_start_1e
    new-instance v4, Ljava/io/FileOutputStream;

    iget-object v0, v2, Llyiahf/vczjk/n92;->OooO0Oo:Ljava/io/File;

    invoke-direct {v4, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    :try_end_1e
    .catchall {:try_start_1e .. :try_end_1e} :catchall_12

    :try_start_1f
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->getChannel()Ljava/nio/channels/FileChannel;

    move-result-object v5
    :try_end_1f
    .catchall {:try_start_1f .. :try_end_1f} :catchall_10

    :try_start_20
    invoke-virtual {v5}, Ljava/nio/channels/FileChannel;->tryLock()Ljava/nio/channels/FileLock;

    move-result-object v6
    :try_end_20
    .catchall {:try_start_20 .. :try_end_20} :catchall_e

    if-eqz v6, :cond_16

    :try_start_21
    invoke-virtual {v6}, Ljava/nio/channels/FileLock;->isValid()Z

    move-result v0

    if-eqz v0, :cond_16

    const/16 v0, 0x200

    new-array v0, v0, [B

    :goto_1f
    invoke-virtual {v3, v0}, Ljava/io/InputStream;->read([B)I

    move-result v7

    if-lez v7, :cond_15

    const/4 v9, 0x0

    invoke-virtual {v4, v0, v9, v7}, Ljava/io/OutputStream;->write([BII)V
    :try_end_21
    .catchall {:try_start_21 .. :try_end_21} :catchall_c

    goto :goto_1f

    :cond_15
    const/4 v7, 0x1

    :try_start_22
    invoke-virtual {v2, v7, v12}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V
    :try_end_22
    .catchall {:try_start_22 .. :try_end_22} :catchall_b

    :try_start_23
    invoke-virtual {v6}, Ljava/nio/channels/FileLock;->close()V
    :try_end_23
    .catchall {:try_start_23 .. :try_end_23} :catchall_a

    :try_start_24
    invoke-virtual {v5}, Ljava/nio/channels/spi/AbstractInterruptibleChannel;->close()V
    :try_end_24
    .catchall {:try_start_24 .. :try_end_24} :catchall_9

    :try_start_25
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V
    :try_end_25
    .catchall {:try_start_25 .. :try_end_25} :catchall_8

    :try_start_26
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    :try_end_26
    .catch Ljava/io/FileNotFoundException; {:try_start_26 .. :try_end_26} :catch_f
    .catch Ljava/io/IOException; {:try_start_26 .. :try_end_26} :catch_e
    .catchall {:try_start_26 .. :try_end_26} :catchall_7

    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oo:[B

    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    move v6, v7

    goto/16 :goto_32

    :catchall_7
    move-exception v0

    goto/16 :goto_33

    :catch_e
    move-exception v0

    goto/16 :goto_2e

    :catch_f
    move-exception v0

    :goto_20
    const/4 v3, 0x6

    goto/16 :goto_30

    :catchall_8
    move-exception v0

    :goto_21
    move-object v4, v0

    goto :goto_2c

    :catchall_9
    move-exception v0

    :goto_22
    move-object v5, v0

    goto :goto_2a

    :catchall_a
    move-exception v0

    :goto_23
    move-object v6, v0

    goto :goto_28

    :catchall_b
    move-exception v0

    :goto_24
    move-object v9, v0

    goto :goto_26

    :cond_16
    const/4 v7, 0x1

    goto :goto_25

    :catchall_c
    move-exception v0

    const/4 v7, 0x1

    goto :goto_24

    :goto_25
    :try_start_27
    new-instance v0, Ljava/io/IOException;

    const-string v9, "Unable to acquire a lock on the underlying file channel."

    invoke-direct {v0, v9}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_27
    .catchall {:try_start_27 .. :try_end_27} :catchall_b

    :goto_26
    if-eqz v6, :cond_17

    :try_start_28
    invoke-virtual {v6}, Ljava/nio/channels/FileLock;->close()V
    :try_end_28
    .catchall {:try_start_28 .. :try_end_28} :catchall_d

    goto :goto_27

    :catchall_d
    move-exception v0

    :try_start_29
    invoke-virtual {v9, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :cond_17
    :goto_27
    throw v9
    :try_end_29
    .catchall {:try_start_29 .. :try_end_29} :catchall_a

    :catchall_e
    move-exception v0

    const/4 v7, 0x1

    goto :goto_23

    :goto_28
    if-eqz v5, :cond_18

    :try_start_2a
    invoke-virtual {v5}, Ljava/nio/channels/spi/AbstractInterruptibleChannel;->close()V
    :try_end_2a
    .catchall {:try_start_2a .. :try_end_2a} :catchall_f

    goto :goto_29

    :catchall_f
    move-exception v0

    :try_start_2b
    invoke-virtual {v6, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :cond_18
    :goto_29
    throw v6
    :try_end_2b
    .catchall {:try_start_2b .. :try_end_2b} :catchall_9

    :catchall_10
    move-exception v0

    const/4 v7, 0x1

    goto :goto_22

    :goto_2a
    :try_start_2c
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V
    :try_end_2c
    .catchall {:try_start_2c .. :try_end_2c} :catchall_11

    goto :goto_2b

    :catchall_11
    move-exception v0

    :try_start_2d
    invoke-virtual {v5, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_2b
    throw v5
    :try_end_2d
    .catchall {:try_start_2d .. :try_end_2d} :catchall_8

    :catchall_12
    move-exception v0

    const/4 v7, 0x1

    goto :goto_21

    :goto_2c
    :try_start_2e
    invoke-virtual {v3}, Ljava/io/InputStream;->close()V
    :try_end_2e
    .catchall {:try_start_2e .. :try_end_2e} :catchall_13

    goto :goto_2d

    :catchall_13
    move-exception v0

    :try_start_2f
    invoke-virtual {v4, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_2d
    throw v4
    :try_end_2f
    .catch Ljava/io/FileNotFoundException; {:try_start_2f .. :try_end_2f} :catch_f
    .catch Ljava/io/IOException; {:try_start_2f .. :try_end_2f} :catch_e
    .catchall {:try_start_2f .. :try_end_2f} :catchall_7

    :catch_10
    move-exception v0

    const/4 v7, 0x1

    goto :goto_2e

    :catch_11
    move-exception v0

    const/4 v7, 0x1

    goto :goto_20

    :goto_2e
    :try_start_30
    invoke-virtual {v2, v8, v0}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V
    :try_end_30
    .catchall {:try_start_30 .. :try_end_30} :catchall_7

    :goto_2f
    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oo:[B

    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    goto :goto_31

    :goto_30
    :try_start_31
    invoke-virtual {v2, v3, v0}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V
    :try_end_31
    .catchall {:try_start_31 .. :try_end_31} :catchall_7

    goto :goto_2f

    :goto_31
    const/4 v6, 0x0

    :goto_32
    if-eqz v6, :cond_19

    invoke-static {v10, v11}, Llyiahf/vczjk/mc4;->OoooO0O(Landroid/content/pm/PackageInfo;Ljava/io/File;)V

    :cond_19
    move v9, v6

    goto :goto_36

    :goto_33
    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oo:[B

    iput-object v12, v2, Llyiahf/vczjk/n92;->OooO0oO:[Llyiahf/vczjk/y92;

    throw v0

    :cond_1a
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :goto_34
    invoke-virtual {v2, v13, v12}, Llyiahf/vczjk/n92;->OooO0O0(ILjava/io/Serializable;)V

    :goto_35
    const/4 v9, 0x0

    :goto_36
    if-eqz v9, :cond_1b

    if-eqz p3, :cond_1b

    move v9, v7

    goto :goto_37

    :cond_1b
    const/4 v9, 0x0

    :goto_37
    invoke-static {v1, v9}, Llyiahf/vczjk/n97;->OooO0OO(Landroid/content/Context;Z)V

    :goto_38
    return-void

    :catch_12
    move-exception v0

    invoke-interface {v5, v8, v0}, Llyiahf/vczjk/i87;->OooO0OO(ILjava/io/Serializable;)V

    const/4 v9, 0x0

    invoke-static {v1, v9}, Llyiahf/vczjk/n97;->OooO0OO(Landroid/content/Context;Z)V

    return-void
.end method


# virtual methods
.method public abstract OooOOOO(ILlyiahf/vczjk/yn4;Llyiahf/vczjk/ow6;I)I
.end method

.method public OooOOOo(Llyiahf/vczjk/ow6;)Ljava/lang/Integer;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/gp1;
    .locals 3

    instance-of v0, p1, Llyiahf/vczjk/gp1;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/gp1;

    return-object p1

    :cond_0
    instance-of v0, p1, Ljava/lang/Class;

    if-eqz v0, :cond_4

    check-cast p1, Ljava/lang/Class;

    const-class v0, Llyiahf/vczjk/ep1;

    if-eq p1, v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    const-class v0, Llyiahf/vczjk/gp1;

    invoke-virtual {v0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/mc4;->Oooo00O()Llyiahf/vczjk/ec5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gp1;

    return-object p1

    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned Class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v2, "; expected Class<Converter>"

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    :goto_0
    const/4 p1, 0x0

    return-object p1

    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned Converter definition of type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "; expected type Converter or Class<Converter> instead"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public abstract Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;
.end method

.method public abstract Oooo00O()Llyiahf/vczjk/ec5;
.end method

.method public abstract Oooo0o(Ljava/lang/Object;)F
.end method

.method public abstract Oooo0o0()Llyiahf/vczjk/a4a;
.end method

.method public OoooO(Llyiahf/vczjk/t66;)Llyiahf/vczjk/p66;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/mc4;->Oooo00O()Llyiahf/vczjk/ec5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    iget-object v1, p1, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    invoke-static {v1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p66;

    iget-object p1, p1, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/p66;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/p66;

    move-result-object p1

    return-object p1
.end method

.method public OoooOO0(Llyiahf/vczjk/t66;)V
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/t66;->OooO0OO:Ljava/lang/Class;

    invoke-virtual {p0}, Llyiahf/vczjk/mc4;->Oooo00O()Llyiahf/vczjk/ec5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    return-void

    :cond_0
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

.method public abstract OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;
.end method

.method public abstract Ooooo00(Ljava/lang/Object;F)V
.end method

.method public o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    const/4 v0, 0x0

    if-nez p1, :cond_0

    move-object p1, v0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/mc4;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    :goto_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mc4;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v0
.end method
