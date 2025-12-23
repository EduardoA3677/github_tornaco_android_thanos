.class public final Llyiahf/vczjk/yl6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationSpec:Llyiahf/vczjk/wl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wl;"
        }
    .end annotation
.end field

.field final synthetic $targetPage:I

.field final synthetic $targetPageOffsetToSnappedPosition:F

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;IFLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yl6;->this$0:Llyiahf/vczjk/lm6;

    iput p2, p0, Llyiahf/vczjk/yl6;->$targetPage:I

    iput p3, p0, Llyiahf/vczjk/yl6;->$targetPageOffsetToSnappedPosition:F

    iput-object p4, p0, Llyiahf/vczjk/yl6;->$animationSpec:Llyiahf/vczjk/wl;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/yl6;

    iget-object v1, p0, Llyiahf/vczjk/yl6;->this$0:Llyiahf/vczjk/lm6;

    iget v2, p0, Llyiahf/vczjk/yl6;->$targetPage:I

    iget v3, p0, Llyiahf/vczjk/yl6;->$targetPageOffsetToSnappedPosition:F

    iget-object v4, p0, Llyiahf/vczjk/yl6;->$animationSpec:Llyiahf/vczjk/wl;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/yl6;-><init>(Llyiahf/vczjk/lm6;IFLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/yl6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yl6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yl6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yl6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v4, p0

    sget-object v6, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, v4, Llyiahf/vczjk/yl6;->label:I

    sget-object v7, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v1, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v7

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v0, v4, Llyiahf/vczjk/yl6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v98;

    iget-object v2, v4, Llyiahf/vczjk/yl6;->this$0:Llyiahf/vczjk/lm6;

    new-instance v3, Llyiahf/vczjk/sl6;

    invoke-direct {v3, v0, v2}, Llyiahf/vczjk/sl6;-><init>(Llyiahf/vczjk/v98;Llyiahf/vczjk/lm6;)V

    iget v0, v4, Llyiahf/vczjk/yl6;->$targetPage:I

    iget v5, v4, Llyiahf/vczjk/yl6;->$targetPageOffsetToSnappedPosition:F

    iget-object v8, v4, Llyiahf/vczjk/yl6;->$animationSpec:Llyiahf/vczjk/wl;

    new-instance v9, Llyiahf/vczjk/xl6;

    invoke-direct {v9, v2}, Llyiahf/vczjk/xl6;-><init>(Llyiahf/vczjk/lm6;)V

    iput v1, v4, Llyiahf/vczjk/yl6;->label:I

    sget v10, Llyiahf/vczjk/qm6;->OooO00o:F

    new-instance v10, Ljava/lang/Integer;

    invoke-direct {v10, v0}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {v9, v3, v10}, Llyiahf/vczjk/xl6;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget v9, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    const/4 v10, 0x0

    if-le v0, v9, :cond_2

    move v9, v1

    goto :goto_0

    :cond_2
    move v9, v10

    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOO0O()Llyiahf/vczjk/ol6;

    move-result-object v11

    iget-object v11, v11, Llyiahf/vczjk/ol6;->OooO00o:Ljava/lang/Object;

    invoke-static {v11}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/of5;

    iget v11, v11, Llyiahf/vczjk/of5;->OooO00o:I

    iget v12, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    sub-int/2addr v11, v12

    add-int/2addr v11, v1

    if-eqz v9, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOO0O()Llyiahf/vczjk/ol6;

    move-result-object v12

    iget-object v12, v12, Llyiahf/vczjk/ol6;->OooO00o:Ljava/lang/Object;

    invoke-static {v12}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/of5;

    iget v12, v12, Llyiahf/vczjk/of5;->OooO00o:I

    if-gt v0, v12, :cond_4

    :cond_3
    if-nez v9, :cond_8

    iget v12, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    if-ge v0, v12, :cond_8

    :cond_4
    iget v12, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    sub-int v12, v0, v12

    invoke-static {v12}, Ljava/lang/Math;->abs(I)I

    move-result v12

    const/4 v13, 0x3

    if-lt v12, v13, :cond_8

    if-eqz v9, :cond_6

    sub-int v9, v0, v11

    iget v11, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    if-ge v9, v11, :cond_7

    :cond_5
    move v9, v11

    goto :goto_1

    :cond_6
    add-int/2addr v11, v0

    iget v9, v2, Llyiahf/vczjk/lm6;->OooO0o0:I

    if-le v11, v9, :cond_5

    :cond_7
    :goto_1
    int-to-float v11, v10

    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v12

    int-to-float v12, v12

    div-float/2addr v11, v12

    invoke-virtual {v2, v11, v9, v1}, Llyiahf/vczjk/lm6;->OooOOoo(FIZ)V

    :cond_8
    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v1

    sub-int/2addr v0, v1

    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v1

    mul-int/2addr v1, v0

    int-to-float v0, v1

    iget-object v1, v2, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {v1}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    move-result v1

    invoke-virtual {v2}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v9

    int-to-float v9, v9

    mul-float/2addr v1, v9

    sub-float/2addr v0, v1

    int-to-float v1, v10

    add-float/2addr v0, v1

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOO0(Llyiahf/vczjk/lm6;)J

    move-result-wide v9

    int-to-long v0, v0

    add-long v11, v9, v0

    iget-wide v13, v2, Llyiahf/vczjk/lm6;->OooO0oo:J

    iget-wide v0, v2, Llyiahf/vczjk/lm6;->OooO0oO:J

    move-wide v15, v0

    invoke-static/range {v11 .. v16}, Llyiahf/vczjk/vt6;->OooOo00(JJJ)J

    move-result-wide v0

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOO0(Llyiahf/vczjk/lm6;)J

    move-result-wide v9

    sub-long/2addr v0, v9

    long-to-int v0, v0

    int-to-float v0, v0

    add-float v1, v0, v5

    new-instance v0, Llyiahf/vczjk/el7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/nm6;

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/nm6;-><init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/sl6;)V

    const/4 v5, 0x4

    const/4 v0, 0x0

    move-object v3, v2

    move-object v2, v8

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vc6;->OooOO0(FFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v6, :cond_9

    goto :goto_2

    :cond_9
    move-object v0, v7

    :goto_2
    if-ne v0, v6, :cond_a

    return-object v6

    :cond_a
    return-object v7
.end method
