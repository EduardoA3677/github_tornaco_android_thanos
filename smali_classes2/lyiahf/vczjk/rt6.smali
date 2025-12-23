.class public final synthetic Llyiahf/vczjk/rt6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/util/ArrayList;

.field public final synthetic OooOOO0:Llyiahf/vczjk/gl7;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/wr0;

.field public final synthetic OooOOo:Llyiahf/vczjk/p29;

.field public final synthetic OooOOo0:F


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/gl7;Ljava/util/ArrayList;FLlyiahf/vczjk/wr0;FLlyiahf/vczjk/p29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rt6;->OooOOO0:Llyiahf/vczjk/gl7;

    iput-object p2, p0, Llyiahf/vczjk/rt6;->OooOOO:Ljava/util/ArrayList;

    iput p3, p0, Llyiahf/vczjk/rt6;->OooOOOO:F

    iput-object p4, p0, Llyiahf/vczjk/rt6;->OooOOOo:Llyiahf/vczjk/wr0;

    iput p5, p0, Llyiahf/vczjk/rt6;->OooOOo0:F

    iput-object p6, p0, Llyiahf/vczjk/rt6;->OooOOo:Llyiahf/vczjk/p29;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/hg2;

    const-string v2, "$this$Canvas"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v2

    iget-object v4, v0, Llyiahf/vczjk/rt6;->OooOOO0:Llyiahf/vczjk/gl7;

    iput-wide v2, v4, Llyiahf/vczjk/gl7;->element:J

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    const/16 v13, 0x20

    shr-long/2addr v2, v13

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v3

    const-wide v14, 0xffffffffL

    and-long/2addr v3, v14

    long-to-int v3, v3

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v4, v2

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    shl-long/2addr v4, v13

    and-long/2addr v2, v14

    or-long v8, v4, v2

    iget-object v2, v0, Llyiahf/vczjk/rt6;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    iget v4, v0, Llyiahf/vczjk/rt6;->OooOOOO:F

    iget-object v5, v0, Llyiahf/vczjk/rt6;->OooOOo:Llyiahf/vczjk/p29;

    if-eqz v3, :cond_1

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0o0:J

    new-instance v16, Llyiahf/vczjk/h79;

    invoke-interface {v1, v4}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v17

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v18, 0x0

    const/16 v21, 0x1e

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    const-wide/16 v6, 0x0

    const/4 v10, 0x0

    const/4 v4, 0x0

    move-object v11, v5

    const/high16 v5, 0x43b40000    # 360.0f

    const/16 v12, 0x350

    move-object/from16 v29, v16

    move-object/from16 v16, v11

    move-object/from16 v11, v29

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/hg2;->OoooOoo(Llyiahf/vczjk/hg2;JFFJJFLlyiahf/vczjk/h79;I)V

    :cond_0
    move/from16 v22, v13

    move-wide/from16 v19, v14

    goto/16 :goto_1

    :cond_1
    move-object/from16 v16, v5

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v17

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ju0;

    invoke-interface/range {v16 .. v16}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    move-result v6

    iget v7, v0, Llyiahf/vczjk/rt6;->OooOOo0:F

    mul-float/2addr v6, v7

    iget v10, v5, Llyiahf/vczjk/ju0;->OooO0O0:F

    mul-float/2addr v6, v10

    mul-float v18, v7, v10

    iget-object v7, v5, Llyiahf/vczjk/ju0;->OooO00o:Llyiahf/vczjk/iu0;

    new-instance v19, Llyiahf/vczjk/h79;

    invoke-interface {v1, v4}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v20

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v21, 0x0

    const/16 v24, 0x1e

    invoke-direct/range {v19 .. v24}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    const-wide/16 v10, 0x0

    move-wide v11, v10

    iget-wide v10, v7, Llyiahf/vczjk/iu0;->OooO0O0:J

    const/16 v12, 0x350

    move/from16 v22, v13

    move v13, v4

    move v4, v2

    move-wide/from16 v29, v14

    move v14, v3

    move-object v15, v5

    move v5, v6

    move-wide v2, v10

    move-object/from16 v11, v19

    const-wide/16 v6, 0x0

    const/4 v10, 0x0

    move-wide/from16 v19, v29

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/hg2;->OoooOoo(Llyiahf/vczjk/hg2;JFFJJFLlyiahf/vczjk/h79;I)V

    add-float/2addr v4, v5

    add-float v18, v14, v18

    sget-wide v2, Llyiahf/vczjk/n21;->OooO:J

    new-instance v23, Llyiahf/vczjk/h79;

    invoke-interface {v1, v13}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v24

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v25, 0x0

    const/16 v28, 0x1e

    invoke-direct/range {v23 .. v28}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    const-wide/16 v6, 0x0

    const/4 v10, 0x0

    const/high16 v5, 0x3f800000    # 1.0f

    const/16 v12, 0x350

    move-object/from16 v11, v23

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/hg2;->OoooOoo(Llyiahf/vczjk/hg2;JFFJJFLlyiahf/vczjk/h79;I)V

    add-float v2, v4, v5

    add-float v3, v18, v5

    iput v14, v15, Llyiahf/vczjk/ju0;->OooO0OO:F

    iput v3, v15, Llyiahf/vczjk/ju0;->OooO0Oo:F

    move v4, v13

    move-wide/from16 v14, v19

    move/from16 v13, v22

    goto :goto_0

    :goto_1
    iget-object v2, v0, Llyiahf/vczjk/rt6;->OooOOOo:Llyiahf/vczjk/wr0;

    if-eqz v2, :cond_2

    new-instance v3, Landroid/graphics/Paint;

    invoke-direct {v3}, Landroid/graphics/Paint;-><init>()V

    const/4 v4, 0x1

    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    sget-object v4, Landroid/graphics/Paint$Align;->CENTER:Landroid/graphics/Paint$Align;

    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setTextAlign(Landroid/graphics/Paint$Align;)V

    iget v4, v2, Llyiahf/vczjk/wr0;->OooO0OO:F

    invoke-interface {v1, v4}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v4

    invoke-interface/range {v16 .. v16}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    move-result v5

    mul-float/2addr v5, v4

    invoke-virtual {v3, v5}, Landroid/graphics/Paint;->setTextSize(F)V

    iget-wide v4, v2, Llyiahf/vczjk/wr0;->OooO0O0:J

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v4

    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setColor(I)V

    sget-object v4, Landroid/graphics/Typeface;->DEFAULT_BOLD:Landroid/graphics/Typeface;

    invoke-virtual {v3, v4}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/t9;->OooO00o(Llyiahf/vczjk/eq0;)Landroid/graphics/Canvas;

    move-result-object v4

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v5

    shr-long v5, v5, v22

    long-to-int v5, v5

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v6

    and-long v6, v6, v19

    long-to-int v1, v6

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    iget-object v2, v2, Llyiahf/vczjk/wr0;->OooO00o:Ljava/lang/String;

    invoke-virtual {v4, v2, v5, v1, v3}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V

    :cond_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
