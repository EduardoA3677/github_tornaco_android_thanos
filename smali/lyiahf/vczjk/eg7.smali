.class public abstract Llyiahf/vczjk/eg7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/dg7;

.field public static final OooO0O0:Llyiahf/vczjk/dg7;


# direct methods
.method static constructor <clinit>()V
    .locals 29

    const/4 v2, 0x6

    const/4 v3, 0x5

    const/4 v4, 0x4

    const/4 v5, 0x3

    const/4 v6, 0x2

    const/4 v7, 0x0

    const/4 v8, 0x1

    new-instance v9, Llyiahf/vczjk/dg7;

    sget-object v11, Llyiahf/vczjk/iu3;->OooO0O0:Llyiahf/vczjk/ima;

    sget-object v12, Llyiahf/vczjk/sp3;->OooOOoo:Llyiahf/vczjk/sp3;

    sget-object v13, Llyiahf/vczjk/fg7;->OooO00o:Llyiahf/vczjk/cua;

    sget-object v14, Llyiahf/vczjk/fg7;->OooO0O0:Llyiahf/vczjk/cua;

    sget-object v15, Llyiahf/vczjk/fg7;->OooO0OO:Llyiahf/vczjk/cua;

    new-instance v10, Llyiahf/vczjk/jm4;

    const/16 v17, 0x8

    const/16 v0, 0xe

    invoke-direct {v10, v0}, Llyiahf/vczjk/jm4;-><init>(I)V

    move-object/from16 v16, v10

    const-string v10, "sRGB"

    invoke-direct/range {v9 .. v16}, Llyiahf/vczjk/dg7;-><init>(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/ze3;)V

    move-object v0, v12

    sput-object v9, Llyiahf/vczjk/eg7;->OooO00o:Llyiahf/vczjk/dg7;

    sget-object v20, Llyiahf/vczjk/uk2;->OooOo00:Llyiahf/vczjk/uk2;

    const-string v10, "Linear sRGB"

    move-object/from16 v12, v20

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    move-result-object v9

    sput-object v9, Llyiahf/vczjk/eg7;->OooO0O0:Llyiahf/vczjk/dg7;

    sget-object v19, Llyiahf/vczjk/fg7;->OooO0Oo:Llyiahf/vczjk/ima;

    sget-object v21, Llyiahf/vczjk/fg7;->OooO0o0:Llyiahf/vczjk/cua;

    sget-object v22, Llyiahf/vczjk/fg7;->OooO0o:Llyiahf/vczjk/cua;

    sget-object v23, Llyiahf/vczjk/fg7;->OooO0oO:Llyiahf/vczjk/cua;

    const-string v18, "ACES2065-1"

    invoke-static/range {v18 .. v23}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    sget-object v23, Llyiahf/vczjk/OooOOO;->OooOOO0:Llyiahf/vczjk/OooOOO;

    sget-object v24, Llyiahf/vczjk/fg7;->OooO0oo:Llyiahf/vczjk/cua;

    sget-object v25, Llyiahf/vczjk/fg7;->OooO:Llyiahf/vczjk/cua;

    sget-object v26, Llyiahf/vczjk/fg7;->OooOO0:Llyiahf/vczjk/cua;

    const-string v21, "ACEScc"

    move-object/from16 v22, v19

    invoke-static/range {v21 .. v26}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    sget-object v23, Llyiahf/vczjk/OooOOOO;->OooOOO0:Llyiahf/vczjk/OooOOOO;

    const-string v21, "ACEScct"

    move-object/from16 v22, v19

    invoke-static/range {v21 .. v26}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    const-string v18, "ACEScg"

    move-object/from16 v21, v24

    move-object/from16 v22, v25

    move-object/from16 v23, v26

    invoke-static/range {v18 .. v23}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    new-instance v12, Llyiahf/vczjk/ag7;

    const-wide v9, 0x4001980000000000L    # 2.19921875

    invoke-direct {v12, v9, v10}, Llyiahf/vczjk/ag7;-><init>(D)V

    new-instance v13, Llyiahf/vczjk/cua;

    const-wide v18, 0x3fe47ae147ae147bL    # 0.64

    invoke-static/range {v18 .. v19}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v9

    const-wide v20, 0x3fd51eb851eb851fL    # 0.33

    invoke-static/range {v20 .. v21}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v10

    invoke-direct {v13, v9, v10}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v14, Llyiahf/vczjk/cua;

    const-wide v9, 0x3fcae147ae147ae1L    # 0.21

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v9

    const-wide v15, 0x3fe6b851eb851eb8L    # 0.71

    invoke-static/range {v15 .. v16}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v10

    invoke-direct {v14, v9, v10}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v15, Llyiahf/vczjk/cua;

    const-wide v22, 0x3fc3333333333333L    # 0.15

    invoke-static/range {v22 .. v23}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v9

    const-wide v24, 0x3faeb851eb851eb8L    # 0.06

    invoke-static/range {v24 .. v25}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v10

    invoke-direct {v15, v9, v10}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v10, "Adobe RGB"

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    sget v9, Llyiahf/vczjk/l40;->OooOOO0:I

    const-wide v9, 0x3fe6a7ef9db22d0eL    # 0.708

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v9

    const-wide v12, 0x3fd2b020c49ba5e3L    # 0.292

    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v10

    const-wide/high16 v12, 0x3ff0000000000000L    # 1.0

    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v14

    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    move-result v9

    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    move-result v10

    invoke-virtual {v14}, Ljava/lang/Number;->floatValue()F

    const-wide v14, 0x3fc5c28f5c28f5c3L    # 0.17

    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v14

    const-wide v15, 0x3fe9810624dd2f1bL    # 0.797

    invoke-static/range {v15 .. v16}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v15

    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v16

    invoke-virtual {v14}, Ljava/lang/Number;->floatValue()F

    move-result v14

    invoke-virtual {v15}, Ljava/lang/Number;->floatValue()F

    move-result v15

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Number;->floatValue()F

    const-wide v26, 0x3fc0c49ba5e353f8L    # 0.131

    invoke-static/range {v26 .. v27}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v16

    const-wide v26, 0x3fa78d4fdf3b645aL    # 0.046

    invoke-static/range {v26 .. v27}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v26

    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v12

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Number;->floatValue()F

    move-result v13

    invoke-virtual/range {v26 .. v26}, Ljava/lang/Number;->floatValue()F

    move-result v16

    invoke-virtual {v12}, Ljava/lang/Number;->floatValue()F

    const-string v12, "RGB"

    invoke-static {v12}, Llyiahf/vczjk/b31;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/y05;

    int-to-float v12, v8

    sub-float v26, v12, v9

    sub-float v26, v26, v10

    sub-float v27, v12, v14

    sub-float v27, v27, v15

    sub-float/2addr v12, v13

    sub-float v12, v12, v16

    const/16 v28, 0x7

    const/16 v1, 0x9

    new-array v1, v1, [F

    aput v9, v1, v7

    aput v14, v1, v8

    aput v13, v1, v6

    aput v10, v1, v5

    aput v15, v1, v4

    aput v16, v1, v3

    aput v26, v1, v2

    aput v27, v1, v28

    aput v12, v1, v17

    invoke-static {v1}, Llyiahf/vczjk/c6a;->OooooOO([F)[F

    move-result-object v9

    iget-object v10, v11, Llyiahf/vczjk/ima;->OooO0O0:Llyiahf/vczjk/cua;

    iget v12, v10, Llyiahf/vczjk/cua;->OooO00o:F

    iget v13, v10, Llyiahf/vczjk/cua;->OooO0OO:F

    mul-float/2addr v12, v13

    iget v14, v10, Llyiahf/vczjk/cua;->OooO0O0:F

    div-float/2addr v12, v14

    invoke-virtual {v10}, Llyiahf/vczjk/cua;->OooO00o()F

    move-result v10

    aget v7, v9, v7

    mul-float/2addr v7, v12

    aget v8, v9, v8

    mul-float/2addr v8, v13

    add-float/2addr v8, v7

    aget v6, v9, v6

    mul-float/2addr v6, v10

    add-float/2addr v6, v8

    aget v5, v9, v5

    mul-float/2addr v5, v12

    aget v4, v9, v4

    mul-float/2addr v4, v13

    add-float/2addr v4, v5

    aget v3, v9, v3

    mul-float/2addr v3, v10

    add-float/2addr v3, v4

    aget v2, v9, v2

    mul-float/2addr v2, v12

    aget v4, v9, v28

    mul-float/2addr v4, v13

    add-float/2addr v4, v2

    aget v2, v9, v17

    mul-float/2addr v2, v10

    add-float/2addr v2, v4

    invoke-static {v6, v3, v2, v1}, Llyiahf/vczjk/c6a;->Oooo0o(FFF[F)[F

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/c6a;->OooooOO([F)[F

    sget-object v12, Llyiahf/vczjk/m40;->OooOOO0:Llyiahf/vczjk/m40;

    new-instance v13, Llyiahf/vczjk/cua;

    invoke-static/range {v18 .. v19}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-static/range {v20 .. v21}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    invoke-direct {v13, v1, v2}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v14, Llyiahf/vczjk/cua;

    const-wide v1, 0x3fd3333333333333L    # 0.3

    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    const-wide v2, 0x3fe3333333333333L    # 0.6

    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    invoke-direct {v14, v1, v2}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v15, Llyiahf/vczjk/cua;

    invoke-static/range {v22 .. v23}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-static/range {v24 .. v25}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    invoke-direct {v15, v1, v2}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v10, "BT.709"

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    new-instance v2, Llyiahf/vczjk/ima;

    new-instance v1, Llyiahf/vczjk/cua;

    const-wide v3, 0x3fd4189374bc6a7fL    # 0.314

    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v3

    const-wide v4, 0x3fd676c8b4395810L    # 0.351

    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v3, "DCI P3"

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/ima;-><init>(Ljava/lang/String;Llyiahf/vczjk/cua;)V

    new-instance v3, Llyiahf/vczjk/ag7;

    const-wide v4, 0x4004cccccccccccdL    # 2.6

    invoke-direct {v3, v4, v5}, Llyiahf/vczjk/ag7;-><init>(D)V

    new-instance v4, Llyiahf/vczjk/cua;

    const-wide v7, 0x3fe5c28f5c28f5c3L    # 0.68

    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    const-wide v9, 0x3fd47ae147ae147bL    # 0.32

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v5

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v5, Llyiahf/vczjk/cua;

    const-wide v12, 0x3fd0f5c28f5c28f6L    # 0.265

    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    const-wide v14, 0x3fe6147ae147ae14L    # 0.69

    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v6

    invoke-direct {v5, v1, v6}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v6, Llyiahf/vczjk/cua;

    invoke-static/range {v22 .. v23}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    move-wide/from16 v16, v7

    invoke-static/range {v24 .. v25}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v7

    invoke-direct {v6, v1, v7}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v1, "DCI P3"

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    move-wide v1, v12

    new-instance v13, Llyiahf/vczjk/cua;

    invoke-static/range {v16 .. v17}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v3

    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v4

    invoke-direct {v13, v3, v4}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    move-wide v3, v14

    new-instance v14, Llyiahf/vczjk/cua;

    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    invoke-direct {v14, v1, v2}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v15, Llyiahf/vczjk/cua;

    invoke-static/range {v22 .. v23}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-static/range {v24 .. v25}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v2

    invoke-direct {v15, v1, v2}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v10, "Display P3"

    move-object v12, v0

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    sget-object v2, Llyiahf/vczjk/iu3;->OooO00o:Llyiahf/vczjk/ima;

    sget-object v3, Llyiahf/vczjk/op3;->Oooo00O:Llyiahf/vczjk/op3;

    new-instance v4, Llyiahf/vczjk/cua;

    const-wide v0, 0x3fe782a9930be0dfL    # 0.7347

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    const-wide v5, 0x3fd0faacd9e83e42L    # 0.2653

    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v5, Llyiahf/vczjk/cua;

    const-wide v0, 0x3fc46dc5d6388659L    # 0.1596

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    const-wide v6, 0x3feae48e8a71de6aL    # 0.8404

    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-direct {v5, v0, v1}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    new-instance v6, Llyiahf/vczjk/cua;

    const-wide v0, 0x3fa2bd3c36113405L    # 0.0366

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    const-wide v7, 0x3f1a36e2eb1c432dL    # 1.0E-4

    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    invoke-direct {v6, v0, v1}, Llyiahf/vczjk/cua;-><init>(Ljava/lang/Double;Ljava/lang/Double;)V

    const-string v1, "ROMM RGB"

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/fg7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/ima;Llyiahf/vczjk/bg7;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;Llyiahf/vczjk/cua;)Llyiahf/vczjk/dg7;

    return-void
.end method
