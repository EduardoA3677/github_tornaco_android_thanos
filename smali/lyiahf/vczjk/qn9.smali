.class public final Llyiahf/vczjk/qn9;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoOO:Ljava/lang/String;

.field public OooOoo:Llyiahf/vczjk/aa3;

.field public OooOoo0:Llyiahf/vczjk/rn9;

.field public OooOooO:I

.field public OooOooo:Z

.field public Oooo0:Ljava/util/HashMap;

.field public Oooo000:I

.field public Oooo00O:I

.field public Oooo00o:Llyiahf/vczjk/w21;

.field public Oooo0O0:Llyiahf/vczjk/fo6;

.field public Oooo0OO:Llyiahf/vczjk/ln9;

.field public Oooo0o0:Llyiahf/vczjk/kn9;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 23

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    iget-object v2, v0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz v2, :cond_1

    iget-boolean v3, v2, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    if-eqz v2, :cond_1

    iget-object v2, v2, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez v2, :cond_2

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object v2

    :cond_2
    invoke-virtual {v2, v1}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    invoke-interface {v1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    iget v4, v2, Llyiahf/vczjk/fo6;->OooO0oO:I

    const/4 v5, 0x1

    if-le v4, v5, :cond_3

    move-wide/from16 v6, p3

    invoke-static {v2, v6, v7, v3}, Llyiahf/vczjk/fo6;->OooO0o0(Llyiahf/vczjk/fo6;JLlyiahf/vczjk/yn4;)J

    move-result-wide v6

    goto :goto_1

    :cond_3
    move-wide/from16 v6, p3

    :goto_1
    iget-object v4, v2, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    const/4 v13, 0x3

    if-nez v4, :cond_4

    :goto_2
    const/16 p3, 0x20

    const-wide v15, 0xffffffffL

    goto/16 :goto_7

    :cond_4
    iget-object v14, v2, Llyiahf/vczjk/fo6;->OooOOO:Llyiahf/vczjk/do6;

    if-nez v14, :cond_5

    goto :goto_2

    :cond_5
    invoke-interface {v14}, Llyiahf/vczjk/do6;->OooO00o()Z

    move-result v14

    if-eqz v14, :cond_6

    goto :goto_2

    :cond_6
    iget-object v14, v2, Llyiahf/vczjk/fo6;->OooOOOO:Llyiahf/vczjk/yn4;

    if-eq v3, v14, :cond_7

    goto :goto_2

    :cond_7
    iget-wide v14, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    invoke-static {v6, v7, v14, v15}, Llyiahf/vczjk/rk1;->OooO0O0(JJ)Z

    move-result v14

    if-eqz v14, :cond_8

    const/16 p3, 0x20

    const-wide v15, 0xffffffffL

    goto :goto_3

    :cond_8
    invoke-static {v6, v7}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v14

    const/16 p3, 0x20

    const-wide v15, 0xffffffffL

    iget-wide v10, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    invoke-static {v10, v11}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v10

    if-eq v14, v10, :cond_9

    goto/16 :goto_7

    :cond_9
    invoke-static {v6, v7}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v10

    iget-wide v11, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    invoke-static {v11, v12}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v11

    if-eq v10, v11, :cond_a

    goto/16 :goto_7

    :cond_a
    invoke-static {v6, v7}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v10

    int-to-float v10, v10

    invoke-virtual {v4}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v11

    cmpg-float v10, v10, v11

    if-ltz v10, :cond_10

    iget-object v4, v4, Llyiahf/vczjk/le;->OooO0Oo:Llyiahf/vczjk/km9;

    iget-boolean v4, v4, Llyiahf/vczjk/km9;->OooO0Oo:Z

    if-eqz v4, :cond_b

    goto :goto_7

    :cond_b
    :goto_3
    iget-wide v3, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    invoke-static {v6, v7, v3, v4}, Llyiahf/vczjk/rk1;->OooO0O0(JJ)Z

    move-result v3

    if-nez v3, :cond_f

    iget-object v3, v2, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v4, v3, Llyiahf/vczjk/le;->OooO00o:Llyiahf/vczjk/pe;

    iget-object v4, v4, Llyiahf/vczjk/pe;->OooO:Llyiahf/vczjk/co4;

    invoke-virtual {v4}, Llyiahf/vczjk/co4;->OooO0OO()F

    move-result v4

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0Oo()F

    move-result v10

    invoke-static {v4, v10}, Ljava/lang/Math;->min(FF)F

    move-result v4

    invoke-static {v4}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result v4

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v10

    invoke-static {v10}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result v10

    int-to-long v11, v4

    shl-long v11, v11, p3

    int-to-long v8, v10

    and-long/2addr v8, v15

    or-long/2addr v8, v11

    invoke-static {v6, v7, v8, v9}, Llyiahf/vczjk/uk1;->OooO0Oo(JJ)J

    move-result-wide v8

    iput-wide v8, v2, Llyiahf/vczjk/fo6;->OooOO0o:J

    iget v10, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    if-ne v10, v13, :cond_c

    goto :goto_4

    :cond_c
    shr-long v10, v8, p3

    long-to-int v10, v10

    int-to-float v10, v10

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0Oo()F

    move-result v11

    cmpg-float v10, v10, v11

    if-ltz v10, :cond_e

    and-long/2addr v8, v15

    long-to-int v8, v8

    int-to-float v8, v8

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v3

    cmpg-float v3, v8, v3

    if-gez v3, :cond_d

    goto :goto_5

    :cond_d
    :goto_4
    const/4 v3, 0x0

    goto :goto_6

    :cond_e
    :goto_5
    move v3, v5

    :goto_6
    iput-boolean v3, v2, Llyiahf/vczjk/fo6;->OooOO0O:Z

    iput-wide v6, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    :cond_f
    const/4 v3, 0x0

    goto/16 :goto_d

    :cond_10
    :goto_7
    invoke-virtual {v2, v3}, Llyiahf/vczjk/fo6;->OooO0Oo(Llyiahf/vczjk/yn4;)Llyiahf/vczjk/do6;

    move-result-object v3

    iget-boolean v8, v2, Llyiahf/vczjk/fo6;->OooO0o0:Z

    iget v9, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    invoke-interface {v3}, Llyiahf/vczjk/do6;->OooO0OO()F

    move-result v10

    invoke-static {v6, v7, v8, v9, v10}, Llyiahf/vczjk/v34;->Oooo0o0(JZIF)J

    move-result-wide v21

    iget-boolean v8, v2, Llyiahf/vczjk/fo6;->OooO0o0:Z

    iget v9, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    iget v10, v2, Llyiahf/vczjk/fo6;->OooO0o:I

    if-nez v8, :cond_13

    const/4 v4, 0x2

    if-ne v9, v4, :cond_11

    goto :goto_8

    :cond_11
    const/4 v8, 0x4

    if-ne v9, v8, :cond_12

    goto :goto_8

    :cond_12
    const/4 v8, 0x5

    if-ne v9, v8, :cond_13

    :goto_8
    move/from16 v19, v5

    goto :goto_9

    :cond_13
    if-ge v10, v5, :cond_14

    goto :goto_8

    :cond_14
    move/from16 v19, v10

    :goto_9
    new-instance v17, Llyiahf/vczjk/le;

    move-object/from16 v18, v3

    check-cast v18, Llyiahf/vczjk/pe;

    move/from16 v20, v9

    invoke-direct/range {v17 .. v22}, Llyiahf/vczjk/le;-><init>(Llyiahf/vczjk/pe;IIJ)V

    move-object/from16 v3, v17

    iput-wide v6, v2, Llyiahf/vczjk/fo6;->OooOOOo:J

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0Oo()F

    move-result v8

    invoke-static {v8}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result v8

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v9

    invoke-static {v9}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result v9

    int-to-long v10, v8

    shl-long v10, v10, p3

    int-to-long v8, v9

    and-long/2addr v8, v15

    or-long/2addr v8, v10

    invoke-static {v6, v7, v8, v9}, Llyiahf/vczjk/uk1;->OooO0Oo(JJ)J

    move-result-wide v6

    iput-wide v6, v2, Llyiahf/vczjk/fo6;->OooOO0o:J

    iget v8, v2, Llyiahf/vczjk/fo6;->OooO0Oo:I

    if-ne v8, v13, :cond_15

    goto :goto_a

    :cond_15
    shr-long v8, v6, p3

    long-to-int v8, v8

    int-to-float v8, v8

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0Oo()F

    move-result v9

    cmpg-float v8, v8, v9

    if-ltz v8, :cond_17

    and-long/2addr v6, v15

    long-to-int v6, v6

    int-to-float v6, v6

    invoke-virtual {v3}, Llyiahf/vczjk/le;->OooO0O0()F

    move-result v7

    cmpg-float v6, v6, v7

    if-gez v6, :cond_16

    goto :goto_b

    :cond_16
    :goto_a
    const/4 v6, 0x0

    goto :goto_c

    :cond_17
    :goto_b
    move v6, v5

    :goto_c
    iput-boolean v6, v2, Llyiahf/vczjk/fo6;->OooOO0O:Z

    iput-object v3, v2, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    move v3, v5

    :goto_d
    iget-object v6, v2, Llyiahf/vczjk/fo6;->OooOOO:Llyiahf/vczjk/do6;

    if-eqz v6, :cond_18

    invoke-interface {v6}, Llyiahf/vczjk/do6;->OooO00o()Z

    :cond_18
    iget-object v6, v2, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v7, v2, Llyiahf/vczjk/fo6;->OooOO0o:J

    if-eqz v3, :cond_1a

    const/4 v4, 0x2

    invoke-static {v0, v4}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/v16;->o0000Oo()V

    iget-object v2, v0, Llyiahf/vczjk/qn9;->Oooo0:Ljava/util/HashMap;

    if-nez v2, :cond_19

    new-instance v2, Ljava/util/HashMap;

    invoke-direct {v2, v4}, Ljava/util/HashMap;-><init>(I)V

    iput-object v2, v0, Llyiahf/vczjk/qn9;->Oooo0:Ljava/util/HashMap;

    :cond_19
    sget-object v3, Llyiahf/vczjk/s4;->OooO00o:Llyiahf/vczjk/go3;

    iget-object v4, v6, Llyiahf/vczjk/le;->OooO0Oo:Llyiahf/vczjk/km9;

    const/4 v6, 0x0

    invoke-virtual {v4, v6}, Llyiahf/vczjk/km9;->OooO0Oo(I)F

    move-result v6

    invoke-static {v6}, Ljava/lang/Math;->round(F)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-interface {v2, v3, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/s4;->OooO0O0:Llyiahf/vczjk/go3;

    iget v6, v4, Llyiahf/vczjk/km9;->OooO0oO:I

    sub-int/2addr v6, v5

    invoke-virtual {v4, v6}, Llyiahf/vczjk/km9;->OooO0Oo(I)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-interface {v2, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1a
    shr-long v2, v7, p3

    long-to-int v2, v2

    and-long v3, v7, v15

    long-to-int v3, v3

    invoke-static {v2, v2, v3, v3}, Llyiahf/vczjk/vc6;->OooOo0(IIII)J

    move-result-wide v4

    move-object/from16 v6, p2

    invoke-interface {v6, v4, v5}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v4

    iget-object v5, v0, Llyiahf/vczjk/qn9;->Oooo0:Ljava/util/HashMap;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v6, Llyiahf/vczjk/pn9;

    invoke-direct {v6, v4}, Llyiahf/vczjk/pn9;-><init>(Llyiahf/vczjk/ow6;)V

    invoke-interface {v1, v2, v3, v5, v6}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object v1

    return-object v1
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 1

    iget-object p2, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz p2, :cond_1

    iget-boolean v0, p2, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez p2, :cond_2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object p2

    :cond_2
    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/fo6;->OooO00o(ILlyiahf/vczjk/yn4;)I

    move-result p1

    return p1
.end method

.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 10

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    goto/16 :goto_5

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz v0, :cond_2

    iget-boolean v1, v0, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez v0, :cond_3

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object v0

    :cond_3
    iget-object v1, v0, Llyiahf/vczjk/fo6;->OooOO0:Llyiahf/vczjk/le;

    if-eqz v1, :cond_e

    iget-object p1, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object p1, p1, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {p1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v2

    iget-boolean p1, v0, Llyiahf/vczjk/fo6;->OooOO0O:Z

    if-eqz p1, :cond_4

    iget-wide v3, v0, Llyiahf/vczjk/fo6;->OooOO0o:J

    const/16 v0, 0x20

    shr-long v5, v3, v0

    long-to-int v0, v5

    int-to-float v5, v0

    const-wide v6, 0xffffffffL

    and-long/2addr v3, v6

    long-to-int v0, v3

    int-to-float v6, v0

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooO0oO()V

    const/4 v7, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-interface/range {v2 .. v7}, Llyiahf/vczjk/eq0;->OooOOOO(FFFFI)V

    :cond_4
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v0, v0, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v3, v0, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    if-nez v3, :cond_5

    sget-object v3, Llyiahf/vczjk/vh9;->OooO0O0:Llyiahf/vczjk/vh9;

    :cond_5
    move-object v6, v3

    iget-object v3, v0, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    if-nez v3, :cond_6

    sget-object v3, Llyiahf/vczjk/ij8;->OooO0Oo:Llyiahf/vczjk/ij8;

    :cond_6
    move-object v5, v3

    iget-object v3, v0, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    if-nez v3, :cond_7

    sget-object v3, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;

    :cond_7
    move-object v7, v3

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_6

    :goto_1
    iget-object v0, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v0}, Llyiahf/vczjk/kl9;->OooO0OO()Llyiahf/vczjk/ri0;

    move-result-object v3

    if-eqz v3, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v0, v0, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v0, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v0}, Llyiahf/vczjk/kl9;->OooO00o()F

    move-result v4

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/le;->OooO0oO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V

    goto :goto_4

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo00o:Llyiahf/vczjk/w21;

    if-eqz v0, :cond_9

    invoke-interface {v0}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v3

    goto :goto_2

    :cond_9
    sget-wide v3, Llyiahf/vczjk/n21;->OooOO0:J

    :goto_2
    const-wide/16 v8, 0x10

    cmp-long v0, v3, v8

    if-eqz v0, :cond_a

    goto :goto_3

    :cond_a
    iget-object v0, p0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    invoke-virtual {v0}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v3

    cmp-long v0, v3, v8

    if-eqz v0, :cond_b

    iget-object v0, p0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    invoke-virtual {v0}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v3

    goto :goto_3

    :cond_b
    sget-wide v3, Llyiahf/vczjk/n21;->OooO0O0:J

    :goto_3
    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/le;->OooO0o(Llyiahf/vczjk/eq0;JLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_4
    if-eqz p1, :cond_c

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooOOo0()V

    :cond_c
    :goto_5
    return-void

    :goto_6
    if-eqz p1, :cond_d

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooOOo0()V

    :cond_d
    throw v0

    :cond_e
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "no paragraph (layoutCache="

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0O0:Llyiahf/vczjk/fo6;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ", textSubstitution="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v0, 0x29

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/sz3;->OooO0O0(Ljava/lang/String;)Ljava/lang/Void;

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 1

    iget-object p2, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz p2, :cond_1

    iget-boolean v0, p2, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez p2, :cond_2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object p2

    :cond_2
    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/fo6;->OooO00o(ILlyiahf/vczjk/yn4;)I

    move-result p1

    return p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz p2, :cond_1

    iget-boolean p3, p2, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz p3, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez p2, :cond_2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object p2

    :cond_2
    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0Oo(Llyiahf/vczjk/yn4;)Llyiahf/vczjk/do6;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/do6;->OooO0O0()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result p1

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0OO:Llyiahf/vczjk/ln9;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/ln9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ln9;-><init>(Llyiahf/vczjk/qn9;)V

    iput-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0OO:Llyiahf/vczjk/ln9;

    :cond_0
    new-instance v1, Llyiahf/vczjk/an;

    iget-object v2, p0, Llyiahf/vczjk/qn9;->OooOoOO:Ljava/lang/String;

    invoke-direct {v1, v2}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ve8;->OooOoO:Llyiahf/vczjk/ze8;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/je8;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz v1, :cond_1

    iget-boolean v2, v1, Llyiahf/vczjk/kn9;->OooO0OO:Z

    sget-object v4, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    sget-object v5, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v6, 0xf

    aget-object v6, v5, v6

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-virtual {v4, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/kn9;->OooO0O0:Ljava/lang/String;

    invoke-direct {v2, v1}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/ve8;->OooOoOO:Llyiahf/vczjk/ze8;

    const/16 v4, 0xe

    aget-object v4, v5, v4

    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    :cond_1
    new-instance v1, Llyiahf/vczjk/mn9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/mn9;-><init>(Llyiahf/vczjk/qn9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOO0O:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    const/4 v5, 0x0

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/nn9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/nn9;-><init>(Llyiahf/vczjk/qn9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/on9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/on9;-><init>(Llyiahf/vczjk/qn9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOOO0:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0OO(Llyiahf/vczjk/af8;Llyiahf/vczjk/oe3;)V

    return-void
.end method

.method public final o00000OO()Llyiahf/vczjk/fo6;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0O0:Llyiahf/vczjk/fo6;

    if-nez v0, :cond_0

    new-instance v1, Llyiahf/vczjk/fo6;

    iget-object v2, p0, Llyiahf/vczjk/qn9;->OooOoOO:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v4, p0, Llyiahf/vczjk/qn9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v5, p0, Llyiahf/vczjk/qn9;->OooOooO:I

    iget-boolean v6, p0, Llyiahf/vczjk/qn9;->OooOooo:Z

    iget v7, p0, Llyiahf/vczjk/qn9;->Oooo000:I

    iget v8, p0, Llyiahf/vczjk/qn9;->Oooo00O:I

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/fo6;-><init>(Ljava/lang/String;Llyiahf/vczjk/rn9;Llyiahf/vczjk/aa3;IZII)V

    iput-object v1, p0, Llyiahf/vczjk/qn9;->Oooo0O0:Llyiahf/vczjk/fo6;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qn9;->Oooo0O0:Llyiahf/vczjk/fo6;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz p2, :cond_1

    iget-boolean p3, p2, Llyiahf/vczjk/kn9;->OooO0OO:Z

    if-eqz p3, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_1

    iget-object p2, p2, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-nez p2, :cond_2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object p2

    :cond_2
    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fo6;->OooO0Oo(Llyiahf/vczjk/yn4;)Llyiahf/vczjk/do6;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/do6;->OooO0OO()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result p1

    return p1
.end method
