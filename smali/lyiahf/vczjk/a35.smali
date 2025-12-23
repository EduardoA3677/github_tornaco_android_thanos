.class public abstract Llyiahf/vczjk/a35;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:Ljava/util/List;

.field public static final OooO0Oo:Ljava/util/List;

.field public static final OooO0o0:F


# direct methods
.method static constructor <clinit>()V
    .locals 21

    sget v0, Llyiahf/vczjk/l35;->OooO0o:F

    sput v0, Llyiahf/vczjk/a35;->OooO00o:F

    sget v1, Llyiahf/vczjk/l35;->OooO0Oo:F

    sput v1, Llyiahf/vczjk/a35;->OooO0O0:F

    sget v2, Llyiahf/vczjk/l35;->OooO00o:F

    sget-object v3, Llyiahf/vczjk/pe5;->OooO00o:Llyiahf/vczjk/vp3;

    invoke-virtual {v3}, Llyiahf/vczjk/vp3;->OooOO0o()Llyiahf/vczjk/aw7;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/pe5;->OooOO0o:Llyiahf/vczjk/aw7;

    const/4 v6, 0x0

    const v7, 0x3f4ccccd    # 0.8f

    const/16 v8, 0xf2

    if-nez v5, :cond_0

    sget-object v5, Llyiahf/vczjk/pe5;->OooO0OO:Llyiahf/vczjk/jr1;

    const/16 v9, 0x9

    invoke-static {v9, v7, v5, v6, v8}, Llyiahf/vczjk/qu6;->OooOo00(IFLlyiahf/vczjk/jr1;Llyiahf/vczjk/jr1;I)Llyiahf/vczjk/aw7;

    move-result-object v5

    sget-object v9, Llyiahf/vczjk/pe5;->OooO0o0:[F

    new-instance v10, Llyiahf/vczjk/cr6;

    invoke-direct {v10, v9}, Llyiahf/vczjk/cr6;-><init>([F)V

    invoke-virtual {v5, v10}, Llyiahf/vczjk/aw7;->OooO0Oo(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/aw7;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v5

    sput-object v5, Llyiahf/vczjk/pe5;->OooOO0o:Llyiahf/vczjk/aw7;

    :cond_0
    sget-object v9, Llyiahf/vczjk/pe5;->OooO:Llyiahf/vczjk/aw7;

    const/4 v10, 0x2

    const/16 v15, 0x20

    if-nez v9, :cond_1

    new-instance v9, Llyiahf/vczjk/me5;

    const/high16 v16, 0x3f000000    # 0.5f

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v12

    const-wide v17, 0xffffffffL

    int-to-long v13, v12

    const v12, -0x43ec8b44    # -0.009f

    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v12

    int-to-long v6, v12

    shl-long v12, v13, v15

    and-long v6, v6, v17

    or-long/2addr v6, v12

    new-instance v12, Llyiahf/vczjk/jr1;

    const v13, 0x3e3020c5    # 0.172f

    invoke-direct {v12, v13, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v9, v6, v7, v12}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    new-instance v6, Llyiahf/vczjk/me5;

    const v7, 0x3f83d70a    # 1.03f

    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    int-to-long v12, v7

    const v7, 0x3ebae148    # 0.365f

    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v7

    move-wide/from16 v19, v12

    int-to-long v11, v7

    shl-long v19, v19, v15

    and-long v11, v11, v17

    or-long v11, v19, v11

    new-instance v7, Llyiahf/vczjk/jr1;

    const v13, 0x3e27ef9e    # 0.164f

    invoke-direct {v7, v13, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v6, v11, v12, v7}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    new-instance v7, Llyiahf/vczjk/me5;

    const v11, 0x3f53f7cf    # 0.828f

    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v11

    int-to-long v11, v11

    const v13, 0x3f7851ec    # 0.97f

    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    move/from16 v19, v15

    int-to-long v14, v13

    shl-long v11, v11, v19

    and-long v13, v14, v17

    or-long/2addr v11, v13

    new-instance v13, Llyiahf/vczjk/jr1;

    const v14, 0x3e2d0e56    # 0.169f

    invoke-direct {v13, v14, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v7, v11, v12, v13}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    filled-new-array {v9, v6, v7}, [Llyiahf/vczjk/me5;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    const/4 v7, 0x1

    const/4 v14, 0x4

    invoke-static {v3, v6, v7, v14}, Llyiahf/vczjk/vp3;->OooO(Llyiahf/vczjk/vp3;Ljava/util/List;II)Llyiahf/vczjk/aw7;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v9

    sput-object v9, Llyiahf/vczjk/pe5;->OooO:Llyiahf/vczjk/aw7;

    :goto_0
    move-object v6, v9

    goto :goto_1

    :cond_1
    move/from16 v19, v15

    const/high16 v16, 0x3f000000    # 0.5f

    const-wide v17, 0xffffffffL

    goto :goto_0

    :goto_1
    sget-object v7, Llyiahf/vczjk/pe5;->OooO0oo:Llyiahf/vczjk/aw7;

    const/high16 v9, 0x3f800000    # 1.0f

    if-nez v7, :cond_2

    new-instance v7, Llyiahf/vczjk/me5;

    const v11, 0x3f760419    # 0.961f

    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v11

    int-to-long v11, v11

    const v13, 0x3d1fbe77    # 0.039f

    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    int-to-long v14, v13

    shl-long v11, v11, v19

    and-long v13, v14, v17

    or-long/2addr v11, v13

    new-instance v13, Llyiahf/vczjk/jr1;

    const v14, 0x3eda1cac    # 0.426f

    invoke-direct {v13, v14, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v7, v11, v12, v13}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    new-instance v11, Llyiahf/vczjk/me5;

    const v12, 0x3f8020c5    # 1.001f

    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v12

    int-to-long v12, v12

    const v14, 0x3edb22d1    # 0.428f

    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v14

    int-to-long v14, v14

    shl-long v12, v12, v19

    and-long v14, v14, v17

    or-long/2addr v12, v14

    sget-object v14, Llyiahf/vczjk/jr1;->OooO0OO:Llyiahf/vczjk/jr1;

    invoke-direct {v11, v12, v13, v14}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    new-instance v12, Llyiahf/vczjk/me5;

    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    int-to-long v13, v13

    const v15, 0x3f1be76d    # 0.609f

    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v15

    int-to-long v8, v15

    shl-long v13, v13, v19

    and-long v8, v8, v17

    or-long/2addr v8, v13

    new-instance v13, Llyiahf/vczjk/jr1;

    const/high16 v14, 0x3f800000    # 1.0f

    invoke-direct {v13, v14, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v12, v8, v9, v13}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    filled-new-array {v7, v11, v12}, [Llyiahf/vczjk/me5;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v7

    const/4 v14, 0x4

    invoke-static {v3, v7, v10, v14}, Llyiahf/vczjk/vp3;->OooO(Llyiahf/vczjk/vp3;Ljava/util/List;II)Llyiahf/vczjk/aw7;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v7

    sput-object v7, Llyiahf/vczjk/pe5;->OooO0oo:Llyiahf/vczjk/aw7;

    :cond_2
    sget-object v8, Llyiahf/vczjk/pe5;->OooOO0:Llyiahf/vczjk/aw7;

    if-nez v8, :cond_3

    sget-object v8, Llyiahf/vczjk/pe5;->OooO0O0:Llyiahf/vczjk/jr1;

    const/16 v9, 0x8

    const/4 v11, 0x0

    const v12, 0x3f4ccccd    # 0.8f

    const/16 v13, 0xf2

    invoke-static {v9, v12, v8, v11, v13}, Llyiahf/vczjk/qu6;->OooOo00(IFLlyiahf/vczjk/jr1;Llyiahf/vczjk/jr1;I)Llyiahf/vczjk/aw7;

    move-result-object v8

    invoke-virtual {v8}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v8

    sput-object v8, Llyiahf/vczjk/pe5;->OooOO0:Llyiahf/vczjk/aw7;

    :cond_3
    sget-object v9, Llyiahf/vczjk/pe5;->OooOO0O:Llyiahf/vczjk/aw7;

    if-nez v9, :cond_4

    new-instance v9, Llyiahf/vczjk/me5;

    const v11, 0x3f9e5604    # 1.237f

    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v11

    int-to-long v11, v11

    const v13, 0x3f9e353f    # 1.236f

    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v13

    int-to-long v14, v13

    shl-long v11, v11, v19

    and-long v13, v14, v17

    or-long/2addr v11, v13

    new-instance v13, Llyiahf/vczjk/jr1;

    const v14, 0x3e841893    # 0.258f

    invoke-direct {v13, v14, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v9, v11, v12, v13}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    new-instance v11, Llyiahf/vczjk/me5;

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v12

    int-to-long v12, v12

    const v14, 0x3f6b020c    # 0.918f

    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v14

    int-to-long v14, v14

    shl-long v12, v12, v19

    and-long v14, v14, v17

    or-long/2addr v12, v14

    new-instance v14, Llyiahf/vczjk/jr1;

    const v15, 0x3e6e978d    # 0.233f

    invoke-direct {v14, v15, v10}, Llyiahf/vczjk/jr1;-><init>(FI)V

    invoke-direct {v11, v12, v13, v14}, Llyiahf/vczjk/me5;-><init>(JLlyiahf/vczjk/jr1;)V

    filled-new-array {v9, v11}, [Llyiahf/vczjk/me5;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    const/16 v10, 0xc

    const/4 v14, 0x4

    invoke-static {v3, v9, v14, v10}, Llyiahf/vczjk/vp3;->OooO(Llyiahf/vczjk/vp3;Ljava/util/List;II)Llyiahf/vczjk/aw7;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v9

    sput-object v9, Llyiahf/vczjk/pe5;->OooOO0O:Llyiahf/vczjk/aw7;

    :cond_4
    sget-object v10, Llyiahf/vczjk/pe5;->OooO0oO:Llyiahf/vczjk/aw7;

    if-nez v10, :cond_5

    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object v10

    const v11, 0x3f23d70a    # 0.64f

    const/high16 v12, 0x3f800000    # 1.0f

    const/4 v14, 0x4

    invoke-static {v10, v12, v11, v14}, Llyiahf/vczjk/ze5;->OooO0oO([FFFI)V

    const/16 v11, 0xf

    const/4 v12, 0x0

    invoke-static {v12, v11}, Llyiahf/vczjk/qu6;->OooO0Oo(II)Llyiahf/vczjk/aw7;

    move-result-object v11

    new-instance v12, Llyiahf/vczjk/cr6;

    invoke-direct {v12, v10}, Llyiahf/vczjk/cr6;-><init>([F)V

    invoke-virtual {v11, v12}, Llyiahf/vczjk/aw7;->OooO0Oo(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/aw7;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/pe5;->OooO0Oo:[F

    new-instance v12, Llyiahf/vczjk/cr6;

    invoke-direct {v12, v11}, Llyiahf/vczjk/cr6;-><init>([F)V

    invoke-virtual {v10, v12}, Llyiahf/vczjk/aw7;->OooO0Oo(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/aw7;

    move-result-object v10

    invoke-virtual {v10}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v10

    sput-object v10, Llyiahf/vczjk/pe5;->OooO0oO:Llyiahf/vczjk/aw7;

    :cond_5
    filled-new-array/range {v4 .. v10}, [Llyiahf/vczjk/aw7;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    sput-object v4, Llyiahf/vczjk/a35;->OooO0OO:Ljava/util/List;

    sget-object v4, Llyiahf/vczjk/pe5;->OooO0o:Llyiahf/vczjk/aw7;

    if-nez v4, :cond_6

    const/16 v4, 0xa

    const/16 v5, 0xe

    invoke-static {v4, v5}, Llyiahf/vczjk/qu6;->OooO0Oo(II)Llyiahf/vczjk/aw7;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/aw7;->OooO0OO()Llyiahf/vczjk/aw7;

    move-result-object v4

    sput-object v4, Llyiahf/vczjk/pe5;->OooO0o:Llyiahf/vczjk/aw7;

    :cond_6
    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object v5

    const/high16 v6, 0x41900000    # 18.0f

    invoke-static {v6, v5}, Llyiahf/vczjk/ze5;->OooO0o0(F[F)V

    new-instance v6, Llyiahf/vczjk/cr6;

    invoke-direct {v6, v5}, Llyiahf/vczjk/cr6;-><init>([F)V

    invoke-virtual {v4, v6}, Llyiahf/vczjk/aw7;->OooO0Oo(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/aw7;

    move-result-object v4

    invoke-virtual {v3}, Llyiahf/vczjk/vp3;->OooOO0o()Llyiahf/vczjk/aw7;

    move-result-object v3

    filled-new-array {v4, v3}, [Llyiahf/vczjk/aw7;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    sput-object v3, Llyiahf/vczjk/a35;->OooO0Oo:Ljava/util/List;

    invoke-static {v0, v1}, Ljava/lang/Math;->min(FF)F

    move-result v0

    div-float/2addr v2, v0

    sput v2, Llyiahf/vczjk/a35;->OooO0o0:F

    return-void
.end method
