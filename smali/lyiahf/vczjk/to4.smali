.class public final Llyiahf/vczjk/to4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hg2;
.implements Llyiahf/vczjk/mm1;


# instance fields
.field public OooOOO:Llyiahf/vczjk/fg2;

.field public final OooOOO0:Llyiahf/vczjk/gq0;


# direct methods
.method public constructor <init>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/gq0;

    invoke-direct {v0}, Llyiahf/vczjk/gq0;-><init>()V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v1, v0, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v3

    iget-object v1, p0, Llyiahf/vczjk/to4;->OooOOO:Llyiahf/vczjk/fg2;

    if-eqz v1, :cond_f

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/jl5;

    iget-object v4, v2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    const/4 v9, 0x4

    const/4 v10, 0x0

    if-nez v4, :cond_0

    goto :goto_1

    :cond_0
    iget v5, v4, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/2addr v5, v9

    if-nez v5, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    if-eqz v4, :cond_4

    iget v5, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v6, v5, 0x2

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    and-int/lit8 v5, v5, 0x4

    if-eqz v5, :cond_3

    goto :goto_2

    :cond_3
    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_4
    :goto_1
    move-object v4, v10

    :goto_2
    if-eqz v4, :cond_d

    move-object v1, v10

    :goto_3
    if-eqz v4, :cond_c

    instance-of v2, v4, Llyiahf/vczjk/fg2;

    if-eqz v2, :cond_5

    move-object v7, v4

    check-cast v7, Llyiahf/vczjk/fg2;

    iget-object v2, v0, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    move-object v8, v2

    check-cast v8, Llyiahf/vczjk/kj3;

    invoke-static {v7, v9}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v6

    iget-wide v4, v6, Llyiahf/vczjk/ow6;->OooOOOO:J

    invoke-static {v4, v5}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v4

    iget-object v2, v6, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa;

    invoke-virtual {v2}, Llyiahf/vczjk/xa;->getSharedDrawScope()Llyiahf/vczjk/to4;

    move-result-object v2

    invoke-virtual/range {v2 .. v8}, Llyiahf/vczjk/to4;->OooO0OO(Llyiahf/vczjk/eq0;JLlyiahf/vczjk/v16;Llyiahf/vczjk/fg2;Llyiahf/vczjk/kj3;)V

    goto :goto_6

    :cond_5
    iget v2, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v2, v9

    if-eqz v2, :cond_b

    instance-of v2, v4, Llyiahf/vczjk/m52;

    if-eqz v2, :cond_b

    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/m52;

    iget-object v2, v2, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v5, 0x0

    :goto_4
    const/4 v6, 0x1

    if-eqz v2, :cond_a

    iget v7, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v7, v9

    if-eqz v7, :cond_9

    add-int/lit8 v5, v5, 0x1

    if-ne v5, v6, :cond_6

    move-object v4, v2

    goto :goto_5

    :cond_6
    if-nez v1, :cond_7

    new-instance v1, Llyiahf/vczjk/ws5;

    const/16 v6, 0x10

    new-array v6, v6, [Llyiahf/vczjk/jl5;

    invoke-direct {v1, v6}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_7
    if-eqz v4, :cond_8

    invoke-virtual {v1, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v10

    :cond_8
    invoke-virtual {v1, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_9
    :goto_5
    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_a
    if-ne v5, v6, :cond_b

    goto :goto_3

    :cond_b
    :goto_6
    invoke-static {v1}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_3

    :cond_c
    return-void

    :cond_d
    invoke-static {v1, v9}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v4

    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    if-ne v4, v2, :cond_e

    iget-object v1, v1, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :cond_e
    iget-object v0, v0, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kj3;

    invoke-virtual {v1, v3, v0}, Llyiahf/vczjk/v16;->o0000oOo(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V

    return-void

    :cond_f
    const-string v0, "Attempting to drawContent for a `null` node. This usually means that a call to ContentDrawScope#drawContent() has been captured inside a lambda, and is being invoked outside of the draw pass. Capturing the scope this way is unsupported - if you are trying to record drawContent with graphicsLayer.record(), make sure you are using the GraphicsLayer#record function within DrawScope, instead of the member function on GraphicsLayer."

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v0

    throw v0
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-virtual {v0}, Llyiahf/vczjk/gq0;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/eq0;JLlyiahf/vczjk/v16;Llyiahf/vczjk/fg2;Llyiahf/vczjk/kj3;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO:Llyiahf/vczjk/fg2;

    iput-object p5, p0, Llyiahf/vczjk/to4;->OooOOO:Llyiahf/vczjk/fg2;

    iget-object v1, p4, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    iget-object v2, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v3, v2, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v4, v3, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/gq0;

    iget-object v4, v4, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v5, v4, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iget-object v4, v4, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v3

    iget-object v2, v2, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v2}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v6

    iget-object v8, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/kj3;

    invoke-virtual {v2, p4}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    invoke-virtual {v2, p1}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v2, p2, p3}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object p6, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    invoke-interface {p1}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    invoke-interface {p5, p0}, Llyiahf/vczjk/fg2;->OooOo0o(Llyiahf/vczjk/to4;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {p1}, Llyiahf/vczjk/eq0;->OooOOo0()V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object v8, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/to4;->OooOOO:Llyiahf/vczjk/fg2;

    return-void

    :catchall_0
    move-exception p2

    invoke-interface {p1}, Llyiahf/vczjk/eq0;->OooOOo0()V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object v8, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    throw p2
.end method

.method public final OooO0o0()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOO0(Llyiahf/vczjk/ri0;JJFLlyiahf/vczjk/ig2;I)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-object v1, p1

    move-wide v2, p2

    move-wide v4, p4

    move v6, p6

    move-object/from16 v7, p7

    move/from16 v8, p8

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/gq0;->OooOO0(Llyiahf/vczjk/ri0;JJFLlyiahf/vczjk/ig2;I)V

    return-void
.end method

.method public final OooOOO(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOOO(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOOO(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooOOo0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOo0(J)F

    move-result p1

    return p1
.end method

.method public final OooOOoo(JJJFI)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-wide v1, p1

    move-wide v3, p3

    move-wide v5, p5

    move/from16 v7, p7

    move/from16 v8, p8

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/gq0;->OooOOoo(JJJFI)V

    return-void
.end method

.method public final OooOo0O(JFFJJFLlyiahf/vczjk/h79;)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-wide v1, p1

    move v3, p3

    move v4, p4

    move-wide/from16 v5, p5

    move-wide/from16 v7, p7

    move/from16 v9, p9

    move-object/from16 v10, p10

    invoke-virtual/range {v0 .. v10}, Llyiahf/vczjk/gq0;->OooOo0O(JFFJJFLlyiahf/vczjk/h79;)V

    return-void
.end method

.method public final OooOoO(JJJFLlyiahf/vczjk/ig2;Llyiahf/vczjk/p21;I)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-wide v1, p1

    move-wide v3, p3

    move-wide/from16 v5, p5

    move/from16 v7, p7

    move-object/from16 v8, p8

    move-object/from16 v9, p9

    move/from16 v10, p10

    invoke-virtual/range {v0 .. v10}, Llyiahf/vczjk/gq0;->OooOoO(JJJFLlyiahf/vczjk/ig2;Llyiahf/vczjk/p21;I)V

    return-void
.end method

.method public final OooOooo(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOooo(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final Oooo000(Llyiahf/vczjk/bq6;JFLlyiahf/vczjk/ig2;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-object v1, p1

    move-wide v2, p2

    move v4, p4

    move-object v5, p5

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/gq0;->Oooo000(Llyiahf/vczjk/bq6;JFLlyiahf/vczjk/ig2;)V

    return-void
.end method

.method public final Oooo0OO(I)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result p1

    return p1
.end method

.method public final Oooo0o(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-virtual {v0}, Llyiahf/vczjk/gq0;->OooO0O0()F

    move-result v0

    div-float/2addr p1, v0

    return p1
.end method

.method public final Oooo0oO(Llyiahf/vczjk/lu3;JJJFLlyiahf/vczjk/p21;I)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-object v1, p1

    move-wide v2, p2

    move-wide v4, p4

    move-wide/from16 v6, p6

    move/from16 v8, p8

    move-object/from16 v9, p9

    move/from16 v10, p10

    invoke-virtual/range {v0 .. v10}, Llyiahf/vczjk/gq0;->Oooo0oO(Llyiahf/vczjk/lu3;JJJFLlyiahf/vczjk/p21;I)V

    return-void
.end method

.method public final OoooO00(JFJLlyiahf/vczjk/ig2;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-wide v1, p1

    move v3, p3

    move-wide v4, p4

    move-object v6, p6

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/gq0;->OoooO00(JFJLlyiahf/vczjk/ig2;)V

    return-void
.end method

.method public final OoooOoO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ig2;I)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-object v4, p4

    move v5, p5

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/gq0;->OoooOoO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ig2;I)V

    return-void
.end method

.method public final Ooooo00(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-virtual {v0}, Llyiahf/vczjk/gq0;->OooO0O0()F

    move-result v0

    mul-float/2addr v0, p1

    return v0
.end method

.method public final Ooooo0o()Llyiahf/vczjk/uqa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v0, v0, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    return-object v0
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v0, v0, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v0, v0, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-virtual {v0}, Llyiahf/vczjk/gq0;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o00Oo0(F)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final o00o0O()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v0

    return-wide v0
.end method

.method public final o00oO0o(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o0ooOO0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o0ooOO0(J)F

    move-result p1

    return p1
.end method

.method public final o0ooOOo(JJJJLlyiahf/vczjk/ig2;F)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    move-wide v1, p1

    move-wide v3, p3

    move-wide/from16 v5, p5

    move-wide/from16 v7, p7

    move-object/from16 v9, p9

    move/from16 v10, p10

    invoke-virtual/range {v0 .. v10}, Llyiahf/vczjk/gq0;->o0ooOOo(JJJJLlyiahf/vczjk/ig2;F)V

    return-void
.end method
