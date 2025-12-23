.class public final Llyiahf/vczjk/rd3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:I = 0x5

.field public static OooO0OO:Z = true

.field public static OooO0Oo:Ljava/lang/reflect/Method; = null

.field public static final OooO0o:I = 0x9

.field public static OooO0o0:Z = false

.field public static final OooO0oO:I = 0x6

.field public static final OooO0oo:I = 0xa

.field public static final OooOO0:I = 0xf

.field public static final OooOO0O:I = 0x30


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Landroid/graphics/Rect;


# direct methods
.method public synthetic constructor <init>(ILandroid/graphics/Rect;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/rd3;->OooO00o:I

    iput-object p2, p0, Llyiahf/vczjk/rd3;->OooO0O0:Landroid/graphics/Rect;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final OooO(I)Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0()Ljava/io/File;

    move-result-object v1

    const-string v2, "data/u/"

    invoke-static {p0, v2}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move/from16 v10, p10

    move-object/from16 v0, p9

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, 0x542c837a

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, p11, 0x1

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
    and-int/lit8 v4, p11, 0x2

    if-eqz v4, :cond_4

    or-int/lit8 v3, v3, 0x30

    :cond_3
    move-object/from16 v5, p1

    goto :goto_3

    :cond_4
    and-int/lit8 v5, v10, 0x30

    if-nez v5, :cond_3

    move-object/from16 v5, p1

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_5

    const/16 v6, 0x20

    goto :goto_2

    :cond_5
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v3, v6

    :goto_3
    and-int/lit16 v6, v10, 0x180

    if-nez v6, :cond_8

    and-int/lit8 v6, p11, 0x4

    if-nez v6, :cond_6

    move-wide/from16 v6, p2

    invoke-virtual {v0, v6, v7}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v8

    if-eqz v8, :cond_7

    const/16 v8, 0x100

    goto :goto_4

    :cond_6
    move-wide/from16 v6, p2

    :cond_7
    const/16 v8, 0x80

    :goto_4
    or-int/2addr v3, v8

    goto :goto_5

    :cond_8
    move-wide/from16 v6, p2

    :goto_5
    and-int/lit16 v8, v10, 0xc00

    if-nez v8, :cond_b

    and-int/lit8 v8, p11, 0x8

    if-nez v8, :cond_9

    move-wide/from16 v8, p4

    invoke-virtual {v0, v8, v9}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v11

    if-eqz v11, :cond_a

    const/16 v11, 0x800

    goto :goto_6

    :cond_9
    move-wide/from16 v8, p4

    :cond_a
    const/16 v11, 0x400

    :goto_6
    or-int/2addr v3, v11

    goto :goto_7

    :cond_b
    move-wide/from16 v8, p4

    :goto_7
    and-int/lit8 v11, p11, 0x10

    if-eqz v11, :cond_d

    or-int/lit16 v3, v3, 0x6000

    :cond_c
    move-object/from16 v12, p6

    goto :goto_9

    :cond_d
    and-int/lit16 v12, v10, 0x6000

    if-nez v12, :cond_c

    move-object/from16 v12, p6

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_e

    const/16 v13, 0x4000

    goto :goto_8

    :cond_e
    const/16 v13, 0x2000

    :goto_8
    or-int/2addr v3, v13

    :goto_9
    and-int/lit8 v13, p11, 0x20

    const/high16 v14, 0x30000

    if-eqz v13, :cond_10

    or-int/2addr v3, v14

    :cond_f
    move/from16 v14, p7

    goto :goto_b

    :cond_10
    and-int/2addr v14, v10

    if-nez v14, :cond_f

    move/from16 v14, p7

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v15

    if-eqz v15, :cond_11

    const/high16 v15, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v15, 0x10000

    :goto_a
    or-int/2addr v3, v15

    :goto_b
    and-int/lit8 v15, p11, 0x40

    const/high16 v16, 0x180000

    if-eqz v15, :cond_13

    or-int v3, v3, v16

    :cond_12
    move-object/from16 v15, p8

    goto :goto_d

    :cond_13
    and-int v15, v10, v16

    if-nez v15, :cond_12

    move-object/from16 v15, p8

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_14

    const/high16 v16, 0x100000

    goto :goto_c

    :cond_14
    const/high16 v16, 0x80000

    :goto_c
    or-int v3, v3, v16

    :goto_d
    const v16, 0x92493

    move/from16 p9, v1

    and-int v1, v3, v16

    const/16 v16, 0x1

    const v2, 0x92492

    move/from16 v17, v3

    const/4 v3, 0x0

    if-eq v1, v2, :cond_15

    move/from16 v1, v16

    goto :goto_e

    :cond_15
    move v1, v3

    :goto_e
    and-int/lit8 v2, v17, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_1e

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v10, 0x1

    if-eqz v1, :cond_17

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_16

    goto :goto_10

    :cond_16
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v17, p0

    :goto_f
    move-object/from16 v18, v5

    move-wide/from16 v19, v6

    move-object/from16 v22, v12

    move/from16 v23, v14

    goto :goto_12

    :cond_17
    :goto_10
    if-eqz p9, :cond_18

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_11

    :cond_18
    move-object/from16 v1, p0

    :goto_11
    if-eqz v4, :cond_19

    sget-object v2, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    move-object v5, v2

    :cond_19
    and-int/lit8 v2, p11, 0x4

    if-eqz v2, :cond_1a

    sget-object v2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/k31;

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0OO()J

    move-result-wide v6

    :cond_1a
    and-int/lit8 v2, p11, 0x8

    if-eqz v2, :cond_1b

    invoke-static {v6, v7, v0}, Llyiahf/vczjk/m31;->OooO00o(JLlyiahf/vczjk/rf1;)J

    move-result-wide v8

    :cond_1b
    if-eqz v11, :cond_1c

    const/4 v2, 0x0

    move-object v12, v2

    :cond_1c
    if-eqz v13, :cond_1d

    int-to-float v2, v3

    move-object/from16 v17, v1

    move/from16 v23, v2

    move-object/from16 v18, v5

    move-wide/from16 v19, v6

    move-object/from16 v22, v12

    goto :goto_12

    :cond_1d
    move-object/from16 v17, v1

    goto :goto_f

    :goto_12
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v1, Llyiahf/vczjk/il2;->OooO0O0:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wd2;

    iget v2, v2, Llyiahf/vczjk/wd2;->OooOOO0:F

    add-float v2, v2, v23

    sget-object v3, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v4, Llyiahf/vczjk/n21;

    invoke-direct {v4, v8, v9}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/wd2;

    invoke-direct {v4, v2}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    filled-new-array {v3, v1}, [Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v16, Llyiahf/vczjk/qa9;

    move/from16 v21, v2

    move-object/from16 v24, v15

    invoke-direct/range {v16 .. v24}, Llyiahf/vczjk/qa9;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;)V

    move-object/from16 v2, v16

    const v3, -0x6c9bf7c6

    invoke-static {v3, v2, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/16 v3, 0x38

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    move-wide v5, v8

    move-object/from16 v1, v17

    move-object/from16 v2, v18

    move-wide/from16 v3, v19

    move-object/from16 v7, v22

    move/from16 v8, v23

    goto :goto_13

    :cond_1e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    move-object v2, v5

    move-wide v3, v6

    move-wide v5, v8

    move-object v7, v12

    move v8, v14

    :goto_13
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v12

    if-eqz v12, :cond_1f

    new-instance v0, Llyiahf/vczjk/sa9;

    move-object/from16 v9, p8

    move/from16 v11, p11

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/sa9;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;II)V

    iput-object v0, v12, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1f
    return-void
.end method

.method public static final OooO0O0(II)J
    .locals 4

    if-ltz p0, :cond_0

    if-ltz p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "start and end cannot be negative. [start: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", end: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    int-to-long v0, p0

    const/16 p0, 0x20

    shl-long/2addr v0, p0

    int-to-long p0, p1

    const-wide v2, 0xffffffffL

    and-long/2addr p0, v2

    or-long/2addr p0, v0

    sget v0, Llyiahf/vczjk/gn9;->OooO0OO:I

    return-wide p0
.end method

.method public static final OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/hy0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public static final OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/hy0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/t09;->OooO0OO:Llyiahf/vczjk/hc3;

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public static final OooO0o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;
    .locals 3

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/t09;->OooOO0O:Llyiahf/vczjk/hy0;

    iget-object v2, v1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-direct {v0, v2, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public static final OooO0o0(Ljava/util/LinkedHashMap;)Ljava/util/LinkedHashMap;
    .locals 4

    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object p0

    check-cast p0, Ljava/lang/Iterable;

    const/16 v0, 0xa

    invoke-static {p0, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v0

    const/16 v1, 0x10

    if-ge v0, v1, :cond_0

    move v0, v1

    :cond_0
    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1, v0}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map$Entry;

    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v2

    invoke-interface {v1, v0, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    return-object v1
.end method

.method public static final OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/hy0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/t09;->OooO0O0:Llyiahf/vczjk/hc3;

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/hy0;
    .locals 3

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/t09;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {p0}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object p0

    const-string v2, "U"

    invoke-virtual {v2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public static final OooOO0()Ljava/io/File;
    .locals 9

    sget-object v0, Llyiahf/vczjk/mz1;->OooO0O0:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0

    :cond_0
    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/mz1;->OooO0O0()Ljava/io/File;

    move-result-object v2

    const-string v3, "thanos"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-static {}, Llyiahf/vczjk/mz1;->OooO00o()Ljava/io/File;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    move-result v4

    const-string v5, "ServiceConfigs DataSystemServerDir baseServerDirMayInit, rename to: "

    if-eqz v4, :cond_1

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/d03;->Oooooo0(Ljava/io/File;)Z

    move-result v1

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " failed. deleted it anyway, deleted? "

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    :cond_2
    :goto_0
    invoke-static {}, Llyiahf/vczjk/mz1;->OooO0O0()Ljava/io/File;

    move-result-object v1

    invoke-virtual {v1}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v1

    if-eqz v1, :cond_4

    array-length v2, v1

    const/4 v4, 0x0

    move v5, v4

    :goto_1
    if-ge v5, v2, :cond_4

    aget-object v6, v1, v5

    invoke-virtual {v6}, Ljava/io/File;->isDirectory()Z

    move-result v7

    if-eqz v7, :cond_3

    invoke-virtual {v6}, Ljava/io/File;->getName()Ljava/lang/String;

    move-result-object v7

    const-string v8, "getName(...)"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7, v3, v4}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-eqz v7, :cond_3

    new-instance v7, Ljava/lang/StringBuilder;

    const-string v8, "ServiceConfigs DataSystemServerDir baseServerDirMayInit, found thanos dir: "

    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    sput-object v6, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    :cond_3
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_4
    sget-object v1, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    if-nez v1, :cond_5

    invoke-static {}, Llyiahf/vczjk/mz1;->OooO00o()Ljava/io/File;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "ServiceConfigs DataSystemServerDir baseServerDirMayInit, new random dir: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    :cond_5
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    sget-object v0, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "ServiceConfigs DataSystemServerDir baseServerDirMayInit, finally we will use: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/mz1;->OooO00o:Ljava/io/File;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public static final OooOO0O()Ljava/io/File;
    .locals 4

    new-instance v0, Ljava/io/File;

    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0()Ljava/io/File;

    move-result-object v2

    const-string v3, "logging"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    const-string v2, "server_logging"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooOO0o(I)Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0()Ljava/io/File;

    move-result-object v1

    const-string v2, "sec_data/u/"

    invoke-static {p0, v2}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, v1, p0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooOOO(IJ)J
    .locals 5

    sget v0, Llyiahf/vczjk/gn9;->OooO0OO:I

    const/16 v0, 0x20

    shr-long v0, p1, v0

    long-to-int v0, v0

    const/4 v1, 0x0

    if-gez v0, :cond_0

    move v2, v1

    goto :goto_0

    :cond_0
    move v2, v0

    :goto_0
    if-le v2, p0, :cond_1

    move v2, p0

    :cond_1
    const-wide v3, 0xffffffffL

    and-long/2addr v3, p1

    long-to-int v3, v3

    if-gez v3, :cond_2

    goto :goto_1

    :cond_2
    move v1, v3

    :goto_1
    if-le v1, p0, :cond_3

    goto :goto_2

    :cond_3
    move p0, v1

    :goto_2
    if-ne v2, v0, :cond_5

    if-eq p0, v3, :cond_4

    goto :goto_3

    :cond_4
    return-wide p1

    :cond_5
    :goto_3
    invoke-static {v2, p0}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOOO0()Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0()Ljava/io/File;

    move-result-object v1

    const-string v2, "tmp"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooOOOO()Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    const/4 v1, 0x0

    invoke-static {v1}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v1

    const-string v2, "config_templates"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooOOOo(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/lu7;
    .locals 1

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p2, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_1

    const-string v0, ":memory:"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/lu7;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/lu7;-><init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V

    return-object v0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Cannot build a database with the special name \':memory:\'. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Cannot build a database with null or empty name. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOOo([Ljava/lang/annotation/Annotation;)Ljava/util/ArrayList;
    .locals 5

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    array-length v1, p0

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    array-length v1, p0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, p0, v2

    new-instance v4, Llyiahf/vczjk/sl7;

    invoke-direct {v4, v3}, Llyiahf/vczjk/sl7;-><init>(Ljava/lang/annotation/Annotation;)V

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public static final OooOOo0([Ljava/lang/annotation/Annotation;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;
    .locals 5

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v0, p0

    const/4 v1, 0x0

    :goto_0
    const/4 v2, 0x0

    if-ge v1, v0, :cond_1

    aget-object v3, p0, v1

    invoke-static {v3}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v4

    invoke-static {v4, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    move-object v3, v2

    :goto_1
    if-eqz v3, :cond_2

    new-instance p0, Llyiahf/vczjk/sl7;

    invoke-direct {p0, v3}, Llyiahf/vczjk/sl7;-><init>(Ljava/lang/annotation/Annotation;)V

    return-object p0

    :cond_2
    return-object v2
.end method

.method public static OooOOoo(Landroidx/activity/ComponentActivity;)Landroid/content/Intent;
    .locals 3

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroid/content/Intent;

    const-string v1, "android.intent.action.OPEN_DOCUMENT_TREE"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1a

    if-lt v1, v2, :cond_1

    const-string v1, ""

    const-string v2, "primary"

    invoke-static {v2, v1}, Llyiahf/vczjk/kd2;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v1

    invoke-static {p0, v1}, Llyiahf/vczjk/qqa;->OooOoo(Landroid/content/Context;Landroid/net/Uri;)Llyiahf/vczjk/op8;

    move-result-object p0

    if-eqz p0, :cond_0

    iget-object p0, p0, Llyiahf/vczjk/op8;->OooO0O0:Landroid/net/Uri;

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    const-string v1, "android.provider.extra.INITIAL_URI"

    invoke-virtual {v0, v1, p0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    :cond_1
    return-object v0
.end method

.method public static OooOo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf;)Llyiahf/vczjk/kl5;
    .locals 1

    new-instance v0, Landroidx/compose/ui/input/pointer/PointerHoverIconModifierElement;

    invoke-direct {v0, p1}, Landroidx/compose/ui/input/pointer/PointerHoverIconModifierElement;-><init>(Llyiahf/vczjk/bf;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo0(Llyiahf/vczjk/j48;)I
    .locals 2

    const-string v0, "SELECT changes()"

    invoke-interface {p0, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object p0

    :try_start_0
    invoke-interface {p0}, Llyiahf/vczjk/l48;->o000000()Z

    const/4 v0, 0x0

    invoke-interface {p0, v0}, Llyiahf/vczjk/l48;->getLong(I)J

    move-result-wide v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    long-to-int v0, v0

    const/4 v1, 0x0

    invoke-static {p0, v1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return v0

    :catchall_0
    move-exception v0

    :try_start_1
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v1

    invoke-static {p0, v0}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw v1
.end method

.method public static final OooOo00(Llyiahf/vczjk/j48;)J
    .locals 3

    invoke-static {p0}, Llyiahf/vczjk/rd3;->OooOo0(Llyiahf/vczjk/j48;)I

    move-result v0

    if-nez v0, :cond_0

    const-wide/16 v0, -0x1

    return-wide v0

    :cond_0
    const-string v0, "SELECT last_insert_rowid()"

    invoke-interface {p0, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object p0

    :try_start_0
    invoke-interface {p0}, Llyiahf/vczjk/l48;->o000000()Z

    const/4 v0, 0x0

    invoke-interface {p0, v0}, Llyiahf/vczjk/l48;->getLong(I)J

    move-result-wide v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v2, 0x0

    invoke-static {p0, v2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-wide v0

    :catchall_0
    move-exception v0

    :try_start_1
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v1

    invoke-static {p0, v0}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw v1
.end method

.method public static final OooOo0o()Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    const/4 v1, 0x0

    invoke-static {v1}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v1

    const-string v2, "plugins"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static OooOoO(Llyiahf/vczjk/qt5;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/qt5;
    .locals 6

    and-int/lit8 v0, p3, 0x4

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    and-int/lit8 p3, p3, 0x8

    const/4 v3, 0x0

    if-eqz p3, :cond_1

    move-object p2, v3

    :cond_1
    iget-boolean p3, p0, Llyiahf/vczjk/qt5;->OooOOO:Z

    if-eqz p3, :cond_2

    goto/16 :goto_4

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0OO()Ljava/lang/String;

    move-result-object p3

    invoke-static {p3, p1, v1}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v4

    if-nez v4, :cond_3

    goto/16 :goto_4

    :cond_3
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    move-result v4

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v5

    if-ne v4, v5, :cond_4

    goto/16 :goto_4

    :cond_4
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v4

    invoke-virtual {p3, v4}, Ljava/lang/String;->charAt(I)C

    move-result v4

    const/16 v5, 0x61

    if-gt v5, v4, :cond_5

    const/16 v5, 0x7b

    if-ge v4, v5, :cond_5

    goto/16 :goto_4

    :cond_5
    if-eqz p2, :cond_6

    invoke-static {p3, p1}, Llyiahf/vczjk/z69;->OoooOoo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p2, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    return-object p0

    :cond_6
    if-nez v0, :cond_7

    return-object p0

    :cond_7
    invoke-static {p3, p1}, Llyiahf/vczjk/z69;->OoooOoo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    if-nez p1, :cond_8

    goto/16 :goto_3

    :cond_8
    invoke-static {v1, p0}, Llyiahf/vczjk/so8;->Oooo000(ILjava/lang/String;)Z

    move-result p1

    if-nez p1, :cond_9

    goto/16 :goto_3

    :cond_9
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    const-string p2, "substring(...)"

    if-eq p1, v2, :cond_e

    invoke-static {v2, p0}, Llyiahf/vczjk/so8;->Oooo000(ILjava/lang/String;)Z

    move-result p1

    if-nez p1, :cond_a

    goto :goto_2

    :cond_a
    new-instance p1, Llyiahf/vczjk/x14;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p3

    sub-int/2addr p3, v2

    invoke-direct {p1, v1, p3, v2}, Llyiahf/vczjk/v14;-><init>(III)V

    invoke-virtual {p1}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object p1

    :cond_b
    iget-boolean p3, p1, Llyiahf/vczjk/w14;->OooOOOO:Z

    if-eqz p3, :cond_c

    invoke-virtual {p1}, Llyiahf/vczjk/n14;->next()Ljava/lang/Object;

    move-result-object p3

    move-object v0, p3

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    invoke-static {v0, p0}, Llyiahf/vczjk/so8;->Oooo000(ILjava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_b

    goto :goto_1

    :cond_c
    move-object p3, v3

    :goto_1
    check-cast p3, Ljava/lang/Integer;

    if-eqz p3, :cond_d

    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    move-result p1

    sub-int/2addr p1, v2

    invoke-virtual {p0, v1, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p3

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p3}, Llyiahf/vczjk/so8;->OoooO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p0, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p3, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    goto :goto_3

    :cond_d
    invoke-static {p0}, Llyiahf/vczjk/so8;->OoooO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    goto :goto_3

    :cond_e
    :goto_2
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p1

    if-nez p1, :cond_f

    goto :goto_3

    :cond_f
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result p1

    const/16 p3, 0x41

    if-gt p3, p1, :cond_10

    const/16 p3, 0x5b

    if-ge p1, p3, :cond_10

    invoke-static {p1}, Ljava/lang/Character;->toLowerCase(C)C

    move-result p1

    invoke-virtual {p0, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    :cond_10
    :goto_3
    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o(Ljava/lang/String;)Z

    move-result p1

    if-nez p1, :cond_11

    :goto_4
    return-object v3

    :cond_11
    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOoO0()Ljava/io/File;
    .locals 3

    new-instance v0, Ljava/io/File;

    const/4 v1, 0x0

    invoke-static {v1}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v1

    const-string v2, "rules"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooOoOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/km6;
    .locals 6

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/zf1;

    const p0, 0x509c4ee5

    invoke-virtual {v3, p0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    const/4 p0, 0x0

    new-array v0, p0, [Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/km6;->OooO0oo:Llyiahf/vczjk/era;

    const v2, -0x404f904f

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-virtual {v3, p0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_0

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v2, :cond_1

    :cond_0
    new-instance v4, Llyiahf/vczjk/om6;

    invoke-direct {v4}, Llyiahf/vczjk/om6;-><init>()V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v4, 0x48

    const/4 v5, 0x4

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/km6;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0
.end method

.method public static final OooOoo(J)D
    .locals 4

    const/16 v0, 0xb

    ushr-long v0, p0, v0

    long-to-double v0, v0

    const/16 v2, 0x800

    int-to-double v2, v2

    mul-double/2addr v0, v2

    const-wide/16 v2, 0x7ff

    and-long/2addr p0, v2

    long-to-double p0, p0

    add-double/2addr v0, p0

    return-wide v0
.end method

.method public static OooOoo0(Landroid/view/ViewGroup;Z)V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1d

    if-lt v0, v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/pga;->OooO0O0(Landroid/view/ViewGroup;Z)V

    return-void

    :cond_0
    sget-boolean v0, Llyiahf/vczjk/rd3;->OooO0OO:Z

    if-eqz v0, :cond_1

    :try_start_0
    invoke-static {p0, p1}, Llyiahf/vczjk/pga;->OooO0O0(Landroid/view/ViewGroup;Z)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodError; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    const/4 p0, 0x0

    sput-boolean p0, Llyiahf/vczjk/rd3;->OooO0OO:Z

    :cond_1
    return-void
.end method

.method public static final OooOooO(Ljava/lang/StringBuilder;Ljava/lang/String;)V
    .locals 1

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->length()I

    move-result v0

    if-lez v0, :cond_0

    const/16 v0, 0x2b

    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_0
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-void
.end method


# virtual methods
.method public final OooOo0O()Landroid/graphics/Rect;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/rd3;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/rd3;->OooO0O0:Landroid/graphics/Rect;

    invoke-virtual {v0}, Landroid/graphics/Rect;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v0, 0x0

    :cond_0
    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/rd3;->OooO0O0:Landroid/graphics/Rect;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
