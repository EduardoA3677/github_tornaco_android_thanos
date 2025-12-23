.class public final synthetic Llyiahf/vczjk/w97;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/dy3;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Llyiahf/vczjk/dy3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/dy3;

.field public final synthetic OooOOoo:J

.field public final synthetic OooOo0:J

.field public final synthetic OooOo00:Llyiahf/vczjk/h79;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/dy3;IFFLlyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;JLlyiahf/vczjk/h79;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w97;->OooOOO0:Llyiahf/vczjk/dy3;

    iput p2, p0, Llyiahf/vczjk/w97;->OooOOO:I

    iput p3, p0, Llyiahf/vczjk/w97;->OooOOOO:F

    iput p4, p0, Llyiahf/vczjk/w97;->OooOOOo:F

    iput-object p5, p0, Llyiahf/vczjk/w97;->OooOOo0:Llyiahf/vczjk/dy3;

    iput-object p6, p0, Llyiahf/vczjk/w97;->OooOOo:Llyiahf/vczjk/dy3;

    iput-wide p7, p0, Llyiahf/vczjk/w97;->OooOOoo:J

    iput-object p9, p0, Llyiahf/vczjk/w97;->OooOo00:Llyiahf/vczjk/h79;

    iput-wide p10, p0, Llyiahf/vczjk/w97;->OooOo0:J

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v1, p0

    iget-wide v5, v1, Llyiahf/vczjk/w97;->OooOOoo:J

    iget-object v7, v1, Llyiahf/vczjk/w97;->OooOo00:Llyiahf/vczjk/h79;

    iget-wide v10, v1, Llyiahf/vczjk/w97;->OooOo0:J

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/hg2;

    iget-object v0, v1, Llyiahf/vczjk/w97;->OooOOO0:Llyiahf/vczjk/dy3;

    invoke-virtual {v0}, Llyiahf/vczjk/dy3;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    const/high16 v3, 0x43b40000    # 360.0f

    mul-float v9, v0, v3

    iget v0, v1, Llyiahf/vczjk/w97;->OooOOO:I

    iget v4, v1, Llyiahf/vczjk/w97;->OooOOOO:F

    const/16 v8, 0x20

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v12

    const-wide v14, 0xffffffffL

    and-long/2addr v12, v14

    long-to-int v0, v12

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v12

    shr-long/2addr v12, v8

    long-to-int v12, v12

    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v12

    cmpl-float v0, v0, v12

    if-lez v0, :cond_1

    goto :goto_0

    :cond_1
    iget v0, v1, Llyiahf/vczjk/w97;->OooOOOo:F

    add-float/2addr v4, v0

    :goto_0
    invoke-interface {v2}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v12

    shr-long/2addr v12, v8

    long-to-int v0, v12

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-interface {v2, v0}, Llyiahf/vczjk/f62;->Oooo0o(F)F

    move-result v0

    float-to-double v12, v0

    const-wide v14, 0x400921fb54442d18L    # Math.PI

    mul-double/2addr v12, v14

    double-to-float v0, v12

    div-float/2addr v4, v0

    mul-float/2addr v4, v3

    iget-object v0, v1, Llyiahf/vczjk/w97;->OooOOo0:Llyiahf/vczjk/dy3;

    invoke-virtual {v0}, Llyiahf/vczjk/dy3;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget-object v8, v1, Llyiahf/vczjk/w97;->OooOOo:Llyiahf/vczjk/dy3;

    invoke-virtual {v8}, Llyiahf/vczjk/dy3;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    move-result v8

    add-float/2addr v8, v0

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v12

    invoke-interface {v2}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v14

    move-wide/from16 v16, v10

    invoke-virtual {v14}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v10

    invoke-virtual {v14}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v0, v14, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vz5;

    invoke-virtual {v0, v8, v12, v13}, Llyiahf/vczjk/vz5;->OooOOOo(FJ)V

    invoke-static {v9, v4}, Ljava/lang/Math;->min(FF)F

    move-result v0

    add-float/2addr v0, v9

    sub-float/2addr v3, v9

    invoke-static {v9, v4}, Ljava/lang/Math;->min(FF)F

    move-result v4

    const/4 v8, 0x2

    int-to-float v8, v8

    mul-float/2addr v4, v8

    sub-float v4, v3, v4

    move v3, v0

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/ea7;->OooO0Oo(Llyiahf/vczjk/hg2;FFJLlyiahf/vczjk/h79;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    const/4 v8, 0x0

    move-object v12, v7

    move-object v7, v2

    move-wide v2, v10

    move-wide/from16 v10, v16

    :try_start_1
    invoke-static/range {v7 .. v12}, Llyiahf/vczjk/ea7;->OooO0Oo(Llyiahf/vczjk/hg2;FFJLlyiahf/vczjk/h79;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-static {v14, v2, v3}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catchall_0
    move-exception v0

    goto :goto_1

    :catchall_1
    move-exception v0

    move-wide v2, v10

    :goto_1
    invoke-static {v14, v2, v3}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw v0
.end method
