.class public final Llyiahf/vczjk/hd2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uca;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/era;

.field public static final OooOOO0:Llyiahf/vczjk/hd2;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    new-instance v0, Llyiahf/vczjk/hd2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/hd2;->OooOOO0:Llyiahf/vczjk/hd2;

    const-string v12, "ps"

    const-string v13, "sz"

    const-string v1, "t"

    const-string v2, "f"

    const-string v3, "s"

    const-string v4, "j"

    const-string v5, "tr"

    const-string v6, "lh"

    const-string v7, "ls"

    const-string v8, "fc"

    const-string v9, "sc"

    const-string v10, "sw"

    const-string v11, "of"

    filled-new-array/range {v1 .. v13}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/era;->OoooO0([Ljava/lang/String;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/hd2;->OooOOO:Llyiahf/vczjk/era;

    return-void
.end method


# virtual methods
.method public final OooOOO(Llyiahf/vczjk/rb4;F)Ljava/lang/Object;
    .locals 17

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooO0oO()V

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x1

    move v5, v2

    move v6, v5

    move v7, v6

    move v8, v7

    move v9, v3

    move v10, v9

    move v11, v10

    move v12, v4

    const/4 v13, 0x3

    move-object v2, v1

    move-object v3, v2

    move-object v4, v3

    :goto_0
    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooOoOO()Z

    move-result v14

    if-eqz v14, :cond_2

    sget-object v14, Llyiahf/vczjk/hd2;->OooOOO:Llyiahf/vczjk/era;

    move-object/from16 v15, p1

    invoke-virtual {v15, v14}, Llyiahf/vczjk/rb4;->o0OoOo0(Llyiahf/vczjk/era;)I

    move-result v14

    packed-switch v14, :pswitch_data_0

    invoke-virtual {v15}, Llyiahf/vczjk/rb4;->o00oO0o()V

    invoke-virtual {v15}, Llyiahf/vczjk/rb4;->o0ooOO0()V

    goto :goto_0

    :pswitch_0
    invoke-virtual {v15}, Llyiahf/vczjk/rb4;->OooO0Oo()V

    new-instance v4, Landroid/graphics/PointF;

    move-object/from16 v16, v1

    const/4 v14, 0x3

    invoke-virtual {v15}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v0

    double-to-float v0, v0

    mul-float v0, v0, p2

    move v1, v14

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v14, v14

    mul-float v14, v14, p2

    invoke-direct {v4, v0, v14}, Landroid/graphics/PointF;-><init>(FF)V

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooOOOO()V

    :goto_1
    move-object/from16 v1, v16

    goto :goto_0

    :pswitch_1
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooO0Oo()V

    new-instance v3, Landroid/graphics/PointF;

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v0, v14

    mul-float v0, v0, p2

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v14, v14

    mul-float v14, v14, p2

    invoke-direct {v3, v0, v14}, Landroid/graphics/PointF;-><init>(FF)V

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooOOOO()V

    goto :goto_1

    :pswitch_2
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooOooo()Z

    move-result v12

    goto :goto_1

    :pswitch_3
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v8, v14

    goto :goto_1

    :pswitch_4
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/sc4;->OooO00o(Llyiahf/vczjk/rb4;)I

    move-result v11

    goto :goto_1

    :pswitch_5
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/sc4;->OooO00o(Llyiahf/vczjk/rb4;)I

    move-result v10

    goto :goto_1

    :pswitch_6
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v7, v14

    goto :goto_1

    :pswitch_7
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v6, v14

    goto :goto_1

    :pswitch_8
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OoooO00()I

    move-result v9

    goto :goto_1

    :pswitch_9
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OoooO00()I

    move-result v0

    const/4 v13, 0x2

    if-gt v0, v13, :cond_1

    if-gez v0, :cond_0

    goto :goto_2

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooOoOO(I)[I

    move-result-object v13

    aget v13, v13, v0

    goto :goto_1

    :cond_1
    :goto_2
    move v13, v1

    goto :goto_1

    :pswitch_a
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v14

    double-to-float v5, v14

    goto :goto_1

    :pswitch_b
    move-object/from16 v16, v1

    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OoooOO0()Ljava/lang/String;

    move-result-object v2

    goto/16 :goto_1

    :pswitch_c
    const/4 v1, 0x3

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OoooOO0()Ljava/lang/String;

    move-result-object v0

    move-object v1, v0

    goto/16 :goto_0

    :cond_2
    move-object/from16 v16, v1

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/rb4;->OooOo()V

    new-instance v0, Llyiahf/vczjk/gd2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    move-object/from16 v1, v16

    iput-object v1, v0, Llyiahf/vczjk/gd2;->OooO00o:Ljava/lang/String;

    iput-object v2, v0, Llyiahf/vczjk/gd2;->OooO0O0:Ljava/lang/String;

    iput v5, v0, Llyiahf/vczjk/gd2;->OooO0OO:F

    iput v13, v0, Llyiahf/vczjk/gd2;->OooO0Oo:I

    iput v9, v0, Llyiahf/vczjk/gd2;->OooO0o0:I

    iput v6, v0, Llyiahf/vczjk/gd2;->OooO0o:F

    iput v7, v0, Llyiahf/vczjk/gd2;->OooO0oO:F

    iput v10, v0, Llyiahf/vczjk/gd2;->OooO0oo:I

    iput v11, v0, Llyiahf/vczjk/gd2;->OooO:I

    iput v8, v0, Llyiahf/vczjk/gd2;->OooOO0:F

    iput-boolean v12, v0, Llyiahf/vczjk/gd2;->OooOO0O:Z

    iput-object v3, v0, Llyiahf/vczjk/gd2;->OooOO0o:Landroid/graphics/PointF;

    iput-object v4, v0, Llyiahf/vczjk/gd2;->OooOOO0:Landroid/graphics/PointF;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
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
