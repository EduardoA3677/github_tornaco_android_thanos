.class public abstract Llyiahf/vczjk/ua9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/na9;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/na9;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/ua9;->OooO00o:Llyiahf/vczjk/jh1;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V
    .locals 1

    and-int/lit8 p10, p11, 0x1

    if-eqz p10, :cond_0

    sget-object p0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :cond_0
    and-int/lit8 p10, p11, 0x2

    if-eqz p10, :cond_1

    sget-object p1, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    :cond_1
    and-int/lit8 p10, p11, 0x4

    if-eqz p10, :cond_2

    sget-object p2, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object p3, p9

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/x21;

    iget-wide p2, p2, Llyiahf/vczjk/x21;->OooOOOo:J

    :cond_2
    and-int/lit8 p10, p11, 0x8

    if-eqz p10, :cond_3

    invoke-static {p2, p3, p9}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide p4

    :cond_3
    and-int/lit8 p10, p11, 0x10

    const/4 v0, 0x0

    if-eqz p10, :cond_4

    int-to-float p6, v0

    :cond_4
    and-int/lit8 p10, p11, 0x20

    if-eqz p10, :cond_5

    int-to-float p7, v0

    :cond_5
    move-object p10, p9

    check-cast p10, Llyiahf/vczjk/zf1;

    sget-object p9, Llyiahf/vczjk/ua9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p10, p9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p11

    check-cast p11, Llyiahf/vczjk/wd2;

    iget p11, p11, Llyiahf/vczjk/wd2;->OooOOO0:F

    add-float/2addr p6, p11

    sget-object p11, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v0, Llyiahf/vczjk/n21;

    invoke-direct {v0, p4, p5}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {p11, v0}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p4

    new-instance p5, Llyiahf/vczjk/wd2;

    invoke-direct {p5, p6}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {p9, p5}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p5

    filled-new-array {p4, p5}, [Llyiahf/vczjk/ke7;

    move-result-object p11

    move-wide p4, p2

    move-object p3, p1

    new-instance p1, Llyiahf/vczjk/pa9;

    move-object p9, p8

    move p8, p7

    const/4 p7, 0x0

    move-object p2, p0

    invoke-direct/range {p1 .. p9}, Llyiahf/vczjk/pa9;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;FLlyiahf/vczjk/a91;)V

    const p0, 0x1923bae6

    invoke-static {p0, p1, p10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object p0

    const/16 p1, 0x38

    invoke-static {p11, p0, p10, p1}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    return-void
.end method

.method public static final OooO0O0(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/se0;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 17

    const/4 v0, 0x0

    int-to-float v1, v0

    move-object/from16 v2, p13

    check-cast v2, Llyiahf/vczjk/zf1;

    if-nez p11, :cond_1

    const v3, 0x2659d109

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v4, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object v3

    :cond_0
    check-cast v3, Llyiahf/vczjk/rr5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v12, v3

    goto :goto_0

    :cond_1
    const v3, -0x1fcb9072

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v12, p11

    :goto_0
    move-object/from16 v0, p13

    check-cast v0, Llyiahf/vczjk/zf1;

    sget-object v2, Llyiahf/vczjk/ua9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/wd2;

    iget v3, v3, Llyiahf/vczjk/wd2;->OooOOO0:F

    add-float v9, v3, v1

    sget-object v1, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v3, Llyiahf/vczjk/n21;

    move-wide/from16 v4, p7

    invoke-direct {v3, v4, v5}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/wd2;

    invoke-direct {v3, v9}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    filled-new-array {v1, v2}, [Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/ta9;

    move/from16 v11, p0

    move-object/from16 v14, p1

    move-object/from16 v5, p2

    move/from16 v13, p3

    move-object/from16 v6, p4

    move-wide/from16 v7, p5

    move/from16 v15, p9

    move-object/from16 v10, p10

    move-object/from16 v16, p12

    invoke-direct/range {v4 .. v16}, Llyiahf/vczjk/ta9;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/oe3;FLlyiahf/vczjk/a91;)V

    const v2, -0x6d9de82e

    invoke-static {v2, v4, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/16 v3, 0x38

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/se0;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V
    .locals 15

    move-object/from16 v0, p13

    move/from16 v1, p15

    and-int/lit8 v2, v1, 0x4

    if-eqz v2, :cond_0

    const/4 v2, 0x1

    move v11, v2

    goto :goto_0

    :cond_0
    move/from16 v11, p2

    :goto_0
    and-int/lit8 v2, v1, 0x20

    move-wide/from16 v6, p4

    if-eqz v2, :cond_1

    invoke-static {v6, v7, v0}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide v2

    goto :goto_1

    :cond_1
    move-wide/from16 v2, p6

    :goto_1
    and-int/lit8 v4, v1, 0x40

    const/4 v5, 0x0

    if-eqz v4, :cond_2

    int-to-float v4, v5

    goto :goto_2

    :cond_2
    move/from16 v4, p8

    :goto_2
    and-int/lit16 v8, v1, 0x80

    if-eqz v8, :cond_3

    int-to-float v8, v5

    move v13, v8

    goto :goto_3

    :cond_3
    move/from16 v13, p9

    :goto_3
    and-int/lit16 v1, v1, 0x100

    if-eqz v1, :cond_4

    const/4 v1, 0x0

    move-object v9, v1

    goto :goto_4

    :cond_4
    move-object/from16 v9, p10

    :goto_4
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    if-nez p11, :cond_6

    const v8, -0x6563c874

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v10, :cond_5

    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object v8

    :cond_5
    check-cast v8, Llyiahf/vczjk/rr5;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v10, v8

    goto :goto_5

    :cond_6
    const v8, 0x7899acab

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v10, p11

    :goto_5
    check-cast v0, Llyiahf/vczjk/zf1;

    sget-object v1, Llyiahf/vczjk/ua9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/wd2;

    iget v5, v5, Llyiahf/vczjk/wd2;->OooOOO0:F

    add-float v8, v5, v4

    sget-object v4, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v5, Llyiahf/vczjk/n21;

    invoke-direct {v5, v2, v3}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/wd2;

    invoke-direct {v3, v8}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    filled-new-array {v2, v1}, [Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/ra9;

    move-object v12, p0

    move-object/from16 v4, p1

    move-object/from16 v5, p3

    move-object/from16 v14, p12

    invoke-direct/range {v3 .. v14}, Llyiahf/vczjk/ra9;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;Llyiahf/vczjk/rr5;ZLlyiahf/vczjk/le3;FLlyiahf/vczjk/a91;)V

    const p0, 0x329de4cf

    invoke-static {p0, v3, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object p0

    const/16 v2, 0x38

    invoke-static {v1, p0, v0, v2}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JLlyiahf/vczjk/se0;F)Llyiahf/vczjk/kl5;
    .locals 10

    const/4 v0, 0x0

    cmpl-float v0, p5, v0

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-lez v0, :cond_0

    const/4 v8, 0x0

    const v9, 0x1e7df

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    move-object v7, p1

    move v5, p5

    invoke-static/range {v1 .. v9}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object v7, p1

    move-object p1, v1

    :goto_0
    invoke-interface {p0, p1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    if-eqz p4, :cond_1

    iget-object p1, p4, Llyiahf/vczjk/se0;->OooO0O0:Llyiahf/vczjk/gx8;

    new-instance v1, Landroidx/compose/foundation/BorderModifierNodeElement;

    iget p4, p4, Llyiahf/vczjk/se0;->OooO00o:F

    invoke-direct {v1, p4, p1, v7}, Landroidx/compose/foundation/BorderModifierNodeElement;-><init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V

    :cond_1
    invoke-interface {p0, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    invoke-static {p0, p2, p3, v7}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object p0

    invoke-static {p0, v7}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(JFLlyiahf/vczjk/zf1;)J
    .locals 3

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    sget-object v1, Llyiahf/vczjk/z21;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    iget-wide v1, v0, Llyiahf/vczjk/x21;->OooOOOo:J

    invoke-static {p0, p1, v1, v2}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v1

    if-eqz v1, :cond_1

    if-eqz p3, :cond_1

    const/4 p0, 0x0

    int-to-float p0, p0

    invoke-static {p2, p0}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p0

    iget-wide v1, v0, Llyiahf/vczjk/x21;->OooOOOo:J

    if-eqz p0, :cond_0

    return-wide v1

    :cond_0
    const/4 p0, 0x1

    int-to-float p0, p0

    add-float/2addr p2, p0

    float-to-double p0, p2

    invoke-static {p0, p1}, Ljava/lang/Math;->log(D)D

    move-result-wide p0

    double-to-float p0, p0

    const/high16 p1, 0x40900000    # 4.5f

    mul-float/2addr p0, p1

    const/high16 p1, 0x40000000    # 2.0f

    add-float/2addr p0, p1

    const/high16 p1, 0x42c80000    # 100.0f

    div-float/2addr p0, p1

    iget-wide p1, v0, Llyiahf/vczjk/x21;->OooOo00:J

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide p0

    invoke-static {p0, p1, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide p0

    :cond_1
    return-wide p0
.end method
