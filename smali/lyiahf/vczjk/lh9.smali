.class public final Llyiahf/vczjk/lh9;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/an;

.field public OooOoo:Llyiahf/vczjk/aa3;

.field public OooOoo0:Llyiahf/vczjk/rn9;

.field public OooOooO:Llyiahf/vczjk/oe3;

.field public OooOooo:I

.field public Oooo:Llyiahf/vczjk/fh9;

.field public Oooo0:Ljava/util/List;

.field public Oooo000:Z

.field public Oooo00O:I

.field public Oooo00o:I

.field public Oooo0O0:Llyiahf/vczjk/oe3;

.field public Oooo0OO:Llyiahf/vczjk/w21;

.field public Oooo0o:Ljava/util/Map;

.field public Oooo0o0:Llyiahf/vczjk/oe3;

.field public Oooo0oO:Llyiahf/vczjk/pq5;

.field public Oooo0oo:Llyiahf/vczjk/gh9;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 8

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v1

    iget v2, v0, Llyiahf/vczjk/pq5;->OooO0o:I

    const/4 v3, 0x1

    if-le v2, v3, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/pq5;->OooO0oo:Llyiahf/vczjk/zj4;

    iget-object v4, v0, Llyiahf/vczjk/pq5;->OooOO0O:Llyiahf/vczjk/rn9;

    iget-object v5, v0, Llyiahf/vczjk/pq5;->OooOO0:Llyiahf/vczjk/f62;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v6, v0, Llyiahf/vczjk/pq5;->OooO0O0:Llyiahf/vczjk/aa3;

    invoke-static {v2, v1, v4, v5, v6}, Llyiahf/vczjk/v34;->Oooo0oO(Llyiahf/vczjk/zj4;Llyiahf/vczjk/yn4;Llyiahf/vczjk/rn9;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)Llyiahf/vczjk/zj4;

    move-result-object v2

    iput-object v2, v0, Llyiahf/vczjk/pq5;->OooO0oo:Llyiahf/vczjk/zj4;

    iget v4, v0, Llyiahf/vczjk/pq5;->OooO0o:I

    invoke-virtual {v2, v4, p3, p4}, Llyiahf/vczjk/zj4;->OooO00o(IJ)J

    move-result-wide p3

    :cond_0
    iget-object v2, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    iget-object v4, v2, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget-object v5, v4, Llyiahf/vczjk/lq5;->OooO00o:Llyiahf/vczjk/oq5;

    invoke-virtual {v5}, Llyiahf/vczjk/oq5;->OooO00o()Z

    move-result v5

    if-eqz v5, :cond_2

    goto :goto_1

    :cond_2
    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v5, v2, Llyiahf/vczjk/lm9;->OooO0oo:Llyiahf/vczjk/yn4;

    if-eq v1, v5, :cond_3

    goto :goto_1

    :cond_3
    iget-wide v5, v2, Llyiahf/vczjk/lm9;->OooOO0:J

    invoke-static {p3, p4, v5, v6}, Llyiahf/vczjk/rk1;->OooO0O0(JJ)Z

    move-result v2

    if-eqz v2, :cond_4

    goto :goto_0

    :cond_4
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v2

    invoke-static {v5, v6}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v7

    if-eq v2, v7, :cond_5

    goto :goto_1

    :cond_5
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v2

    invoke-static {v5, v6}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v5

    if-eq v2, v5, :cond_6

    goto :goto_1

    :cond_6
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v2

    int-to-float v2, v2

    iget v5, v4, Llyiahf/vczjk/lq5;->OooO0o0:F

    cmpg-float v2, v2, v5

    if-ltz v2, :cond_9

    iget-boolean v2, v4, Llyiahf/vczjk/lq5;->OooO0OO:Z

    if-eqz v2, :cond_7

    goto :goto_1

    :cond_7
    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-wide v4, v2, Llyiahf/vczjk/lm9;->OooOO0:J

    invoke-static {p3, p4, v4, v5}, Llyiahf/vczjk/rk1;->OooO0O0(JJ)Z

    move-result v2

    if-eqz v2, :cond_8

    const/4 v3, 0x0

    goto :goto_2

    :cond_8
    iget-object v2, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v0, v1, p3, p4, v2}, Llyiahf/vczjk/pq5;->OooO0o0(Llyiahf/vczjk/yn4;JLlyiahf/vczjk/lq5;)Llyiahf/vczjk/mm9;

    move-result-object p3

    iput-object p3, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    goto :goto_2

    :cond_9
    :goto_1
    invoke-virtual {v0, p3, p4, v1}, Llyiahf/vczjk/pq5;->OooO0O0(JLlyiahf/vczjk/yn4;)Llyiahf/vczjk/lq5;

    move-result-object v2

    invoke-virtual {v0, v1, p3, p4, v2}, Llyiahf/vczjk/pq5;->OooO0o0(Llyiahf/vczjk/yn4;JLlyiahf/vczjk/lq5;)Llyiahf/vczjk/mm9;

    move-result-object p3

    iput-object p3, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    :goto_2
    iget-object p3, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    if-eqz p3, :cond_e

    iget-object p4, p3, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget-object p4, p4, Llyiahf/vczjk/lq5;->OooO00o:Llyiahf/vczjk/oq5;

    invoke-virtual {p4}, Llyiahf/vczjk/oq5;->OooO00o()Z

    if-eqz v3, :cond_c

    const/4 p4, 0x2

    invoke-static {p0, p4}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000Oo()V

    iget-object v0, p0, Llyiahf/vczjk/lh9;->OooOooO:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_a

    invoke-interface {v0, p3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_a
    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0o:Ljava/util/Map;

    if-nez v0, :cond_b

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0, p4}, Ljava/util/LinkedHashMap;-><init>(I)V

    :cond_b
    sget-object p4, Llyiahf/vczjk/s4;->OooO00o:Llyiahf/vczjk/go3;

    iget v1, p3, Llyiahf/vczjk/mm9;->OooO0Oo:F

    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {v0, p4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p4, Llyiahf/vczjk/s4;->OooO0O0:Llyiahf/vczjk/go3;

    iget v1, p3, Llyiahf/vczjk/mm9;->OooO0o0:F

    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {v0, p4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0o:Ljava/util/Map;

    :cond_c
    iget-object p4, p0, Llyiahf/vczjk/lh9;->Oooo0O0:Llyiahf/vczjk/oe3;

    if-eqz p4, :cond_d

    iget-object v0, p3, Llyiahf/vczjk/mm9;->OooO0o:Ljava/util/ArrayList;

    invoke-interface {p4, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_d
    const/16 p4, 0x20

    iget-wide v0, p3, Llyiahf/vczjk/mm9;->OooO0OO:J

    shr-long p3, v0, p4

    long-to-int p3, p3

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int p4, v0

    invoke-static {p3, p3, p4, p4}, Llyiahf/vczjk/vc6;->OooOo0(IIII)J

    move-result-wide v0

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0o:Ljava/util/Map;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/kh9;

    invoke-direct {v1, p2}, Llyiahf/vczjk/kh9;-><init>(Llyiahf/vczjk/ow6;)V

    invoke-interface {p1, p3, p4, v0, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :cond_e
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "You must call layoutWithConstraints first"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/pq5;->OooO00o(ILlyiahf/vczjk/yn4;)I

    move-result p1

    return p1
.end method

.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 13

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    goto/16 :goto_a

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v0, v0, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    if-eqz v0, :cond_15

    iget-wide v3, v0, Llyiahf/vczjk/mm9;->OooO0OO:J

    const/16 v1, 0x20

    shr-long v5, v3, v1

    long-to-int v5, v5

    int-to-float v5, v5

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget v6, v0, Llyiahf/vczjk/lq5;->OooO0Oo:F

    cmpg-float v5, v5, v6

    const/4 v8, 0x1

    const/4 v9, 0x0

    const-wide v6, 0xffffffffL

    if-gez v5, :cond_1

    goto :goto_0

    :cond_1
    iget-boolean v5, v0, Llyiahf/vczjk/lq5;->OooO0OO:Z

    if-nez v5, :cond_3

    and-long v10, v3, v6

    long-to-int v5, v10

    int-to-float v5, v5

    iget v10, v0, Llyiahf/vczjk/lq5;->OooO0o0:F

    cmpg-float v5, v5, v10

    if-gez v5, :cond_2

    goto :goto_0

    :cond_2
    move v5, v9

    goto :goto_1

    :cond_3
    :goto_0
    move v5, v8

    :goto_1
    if-eqz v5, :cond_5

    iget v5, p0, Llyiahf/vczjk/lh9;->OooOooo:I

    const/4 v10, 0x3

    if-ne v5, v10, :cond_4

    goto :goto_2

    :cond_4
    move v10, v8

    goto :goto_3

    :cond_5
    :goto_2
    move v10, v9

    :goto_3
    if-eqz v10, :cond_6

    shr-long v11, v3, v1

    long-to-int v5, v11

    int-to-float v5, v5

    and-long/2addr v3, v6

    long-to-int v3, v3

    int-to-float v3, v3

    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v4, v4

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v11, v3

    shl-long v3, v4, v1

    and-long v5, v11, v6

    or-long/2addr v3, v5

    const-wide/16 v5, 0x0

    invoke-static {v5, v6, v3, v4}, Llyiahf/vczjk/ll6;->OooO0O0(JJ)Llyiahf/vczjk/wj7;

    move-result-object v1

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooO0oO()V

    invoke-static {v2, v1}, Llyiahf/vczjk/eq0;->OooOOO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/wj7;)V

    :cond_6
    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v1, v1, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v3, v1, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    if-nez v3, :cond_7

    sget-object v3, Llyiahf/vczjk/vh9;->OooO0O0:Llyiahf/vczjk/vh9;

    :cond_7
    move-object v6, v3

    iget-object v3, v1, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    if-nez v3, :cond_8

    sget-object v3, Llyiahf/vczjk/ij8;->OooO0Oo:Llyiahf/vczjk/ij8;

    :cond_8
    move-object v5, v3

    iget-object v3, v1, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    if-nez v3, :cond_9

    sget-object v3, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;

    :cond_9
    move-object v7, v3

    goto :goto_4

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto/16 :goto_c

    :goto_4
    iget-object v1, v1, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v1}, Llyiahf/vczjk/kl9;->OooO0OO()Llyiahf/vczjk/ri0;

    move-result-object v3

    if-eqz v3, :cond_a

    iget-object v1, p0, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v1, v1, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v1, v1, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v1}, Llyiahf/vczjk/kl9;->OooO00o()F

    move-result v4

    move-object v1, v0

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/lq5;->OooOO0(Llyiahf/vczjk/lq5;Llyiahf/vczjk/eq0;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V

    goto :goto_7

    :cond_a
    move-object v1, v0

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0OO:Llyiahf/vczjk/w21;

    if-eqz v0, :cond_b

    invoke-interface {v0}, Llyiahf/vczjk/w21;->OooO00o()J

    move-result-wide v3

    goto :goto_5

    :cond_b
    sget-wide v3, Llyiahf/vczjk/n21;->OooOO0:J

    :goto_5
    const-wide/16 v11, 0x10

    cmp-long v0, v3, v11

    if-eqz v0, :cond_c

    goto :goto_6

    :cond_c
    iget-object v0, p0, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    invoke-virtual {v0}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v3

    cmp-long v0, v3, v11

    if-eqz v0, :cond_d

    iget-object v0, p0, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    invoke-virtual {v0}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v3

    goto :goto_6

    :cond_d
    sget-wide v3, Llyiahf/vczjk/n21;->OooO0O0:J

    :goto_6
    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/lq5;->OooO(Llyiahf/vczjk/lq5;Llyiahf/vczjk/eq0;JLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_7
    if-eqz v10, :cond_e

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooOOo0()V

    :cond_e
    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    if-eqz v0, :cond_f

    iget-boolean v0, v0, Llyiahf/vczjk/fh9;->OooO0OO:Z

    if-ne v0, v8, :cond_f

    move v0, v9

    goto :goto_8

    :cond_f
    iget-object v0, p0, Llyiahf/vczjk/lh9;->OooOoOO:Llyiahf/vczjk/an;

    invoke-static {v0}, Llyiahf/vczjk/mt6;->OooOOOo(Llyiahf/vczjk/an;)Z

    move-result v0

    :goto_8
    if-nez v0, :cond_13

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0:Ljava/util/List;

    if-eqz v0, :cond_11

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_10

    goto :goto_9

    :cond_10
    move v8, v9

    :cond_11
    :goto_9
    if-nez v8, :cond_12

    goto :goto_b

    :cond_12
    :goto_a
    return-void

    :cond_13
    :goto_b
    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    return-void

    :goto_c
    if-eqz v10, :cond_14

    invoke-interface {v2}, Llyiahf/vczjk/eq0;->OooOOo0()V

    :cond_14
    throw p1

    :cond_15
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "You must call layoutWithConstraints first"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/pq5;->OooO00o(ILlyiahf/vczjk/yn4;)I

    move-result p1

    return p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/pq5;->OooO0Oo(Llyiahf/vczjk/yn4;)Llyiahf/vczjk/oq5;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/oq5;->OooO0O0()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result p1

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0oo:Llyiahf/vczjk/gh9;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/gh9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/gh9;-><init>(Llyiahf/vczjk/lh9;)V

    iput-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0oo:Llyiahf/vczjk/gh9;

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/lh9;->OooOoOO:Llyiahf/vczjk/an;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ve8;->OooOoO:Llyiahf/vczjk/ze8;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/je8;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    if-eqz v1, :cond_1

    iget-object v2, v1, Llyiahf/vczjk/fh9;->OooO0O0:Llyiahf/vczjk/an;

    sget-object v4, Llyiahf/vczjk/ve8;->OooOoOO:Llyiahf/vczjk/ze8;

    sget-object v5, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v6, 0xe

    aget-object v6, v5, v6

    invoke-virtual {v4, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    iget-boolean v1, v1, Llyiahf/vczjk/fh9;->OooO0OO:Z

    sget-object v2, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    const/16 v4, 0xf

    aget-object v4, v5, v4

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v2, p1, v1}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    :cond_1
    new-instance v1, Llyiahf/vczjk/hh9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/hh9;-><init>(Llyiahf/vczjk/lh9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOO0O:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    const/4 v5, 0x0

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/ih9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/ih9;-><init>(Llyiahf/vczjk/lh9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/jh9;

    invoke-direct {v1, p0}, Llyiahf/vczjk/jh9;-><init>(Llyiahf/vczjk/lh9;)V

    sget-object v2, Llyiahf/vczjk/ie8;->OooOOO0:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v3, v2, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0OO(Llyiahf/vczjk/af8;Llyiahf/vczjk/oe3;)V

    return-void
.end method

.method public final o00000OO()Llyiahf/vczjk/pq5;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0oO:Llyiahf/vczjk/pq5;

    if-nez v0, :cond_0

    new-instance v1, Llyiahf/vczjk/pq5;

    iget-object v2, p0, Llyiahf/vczjk/lh9;->OooOoOO:Llyiahf/vczjk/an;

    iget-object v3, p0, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v4, p0, Llyiahf/vczjk/lh9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v5, p0, Llyiahf/vczjk/lh9;->OooOooo:I

    iget-boolean v6, p0, Llyiahf/vczjk/lh9;->Oooo000:Z

    iget v7, p0, Llyiahf/vczjk/lh9;->Oooo00O:I

    iget v8, p0, Llyiahf/vczjk/lh9;->Oooo00o:I

    iget-object v9, p0, Llyiahf/vczjk/lh9;->Oooo0:Ljava/util/List;

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/pq5;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Llyiahf/vczjk/aa3;IZIILjava/util/List;)V

    iput-object v1, p0, Llyiahf/vczjk/lh9;->Oooo0oO:Llyiahf/vczjk/pq5;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo0oO:Llyiahf/vczjk/pq5;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    if-eqz v0, :cond_0

    iget-boolean v1, v0, Llyiahf/vczjk/fh9;->OooO0OO:Z

    if-eqz v1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/fh9;->OooO0Oo:Llyiahf/vczjk/pq5;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pq5;->OooO0OO(Llyiahf/vczjk/f62;)V

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/lh9;->o00000OO()Llyiahf/vczjk/pq5;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pq5;->OooO0OO(Llyiahf/vczjk/f62;)V

    return-object v0
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/lh9;->o00000Oo(Llyiahf/vczjk/f62;)Llyiahf/vczjk/pq5;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/pq5;->OooO0Oo(Llyiahf/vczjk/yn4;)Llyiahf/vczjk/oq5;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/oq5;->OooO0OO()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/xt6;->OooOo(F)I

    move-result p1

    return p1
.end method
