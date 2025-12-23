.class public abstract Landroidx/compose/material3/internal/OooO0O0;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Landroidx/compose/material3/internal/OooO00o;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Landroidx/compose/material3/internal/OooO00o;

    iget v1, v0, Landroidx/compose/material3/internal/OooO00o;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Landroidx/compose/material3/internal/OooO00o;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Landroidx/compose/material3/internal/OooO00o;

    invoke-direct {v0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Landroidx/compose/material3/internal/OooO00o;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Landroidx/compose/material3/internal/OooO00o;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/i7; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    new-instance p2, Llyiahf/vczjk/a8;

    const/4 v2, 0x0

    invoke-direct {p2, p0, p1, v2}, Llyiahf/vczjk/a8;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput v3, v0, Landroidx/compose/material3/internal/OooO00o;->label:I

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0
    :try_end_1
    .catch Llyiahf/vczjk/i7; {:try_start_1 .. :try_end_1} :catch_0

    if-ne p0, v1, :cond_3

    return-object v1

    :catch_0
    :cond_3
    :goto_1
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/c9;Llyiahf/vczjk/nf6;ZZI)Llyiahf/vczjk/kl5;
    .locals 10

    and-int/lit8 p5, p5, 0x8

    const/4 v0, 0x0

    if-eqz p5, :cond_0

    move v8, v0

    goto :goto_0

    :cond_0
    move v8, p4

    :goto_0
    iget-object v2, p1, Llyiahf/vczjk/c9;->OooO0o:Llyiahf/vczjk/x8;

    iget-object p4, p1, Llyiahf/vczjk/c9;->OooOO0o:Llyiahf/vczjk/qs5;

    check-cast p4, Llyiahf/vczjk/fw8;

    invoke-virtual {p4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p4

    if-eqz p4, :cond_1

    const/4 v0, 0x1

    :cond_1
    move v6, v0

    new-instance v7, Llyiahf/vczjk/n7;

    const/4 p4, 0x0

    invoke-direct {v7, p1, p4}, Llyiahf/vczjk/n7;-><init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;)V

    const/16 v9, 0x20

    const/4 v5, 0x0

    move-object v1, p0

    move-object v3, p2

    move v4, p3

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/uf2;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/bf3;ZI)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)Llyiahf/vczjk/kl5;
    .locals 11

    new-instance v0, Landroidx/compose/material3/internal/IndeterminateCircularWavyProgressElement;

    move-wide v1, p1

    move-wide v3, p3

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move/from16 v7, p7

    move/from16 v8, p8

    move/from16 v9, p9

    move/from16 v10, p10

    invoke-direct/range {v0 .. v10}, Landroidx/compose/material3/internal/IndeterminateCircularWavyProgressElement;-><init>(JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/c9;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/kl5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    new-instance v0, Landroidx/compose/material3/internal/DraggableAnchorsElement;

    invoke-direct {v0, p1, p2}, Landroidx/compose/material3/internal/DraggableAnchorsElement;-><init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/ze3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)Llyiahf/vczjk/kl5;
    .locals 15

    new-instance v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;

    move-object/from16 v9, p1

    move-object/from16 v10, p2

    move-object/from16 v11, p3

    move-object/from16 v12, p4

    move-wide/from16 v5, p5

    move-wide/from16 v7, p7

    move-object/from16 v13, p9

    move-object/from16 v14, p10

    move/from16 v1, p11

    move/from16 v4, p12

    move/from16 v2, p13

    move/from16 v3, p14

    invoke-direct/range {v0 .. v14}, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;-><init>(FFFFJJLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/h79;Llyiahf/vczjk/h79;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
