.class public final Llyiahf/vczjk/bq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bq1;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/bq1;->$value:Llyiahf/vczjk/gl9;

    iput-object p3, p0, Llyiahf/vczjk/bq1;->$offsetMapping:Llyiahf/vczjk/s86;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/hg2;

    iget-object v0, p0, Llyiahf/vczjk/bq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    if-eqz v0, :cond_12

    iget-object v1, p0, Llyiahf/vczjk/bq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v2, p0, Llyiahf/vczjk/bq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v3, p0, Llyiahf/vczjk/bq1;->$offsetMapping:Llyiahf/vczjk/s86;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v5

    iget-object p1, v2, Llyiahf/vczjk/lx4;->OooOoO:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gn9;

    iget-wide v6, p1, Llyiahf/vczjk/gn9;->OooO00o:J

    iget-object p1, v2, Llyiahf/vczjk/lx4;->OooOoOO:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gn9;

    iget-wide v8, p1, Llyiahf/vczjk/gn9;->OooO00o:J

    iget-wide v10, v2, Llyiahf/vczjk/lx4;->OooOoO0:J

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    iget-object v0, v0, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    iget-object v2, v2, Llyiahf/vczjk/lx4;->OooOo:Llyiahf/vczjk/ie;

    if-nez p1, :cond_0

    invoke-virtual {v2, v10, v11}, Llyiahf/vczjk/ie;->OooOOOo(J)V

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p1

    invoke-interface {v3, p1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result p1

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    invoke-interface {v3, v1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result v1

    if-eq p1, v1, :cond_4

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/mm9;->OooO0oo(II)Llyiahf/vczjk/qe;

    move-result-object p1

    invoke-interface {v5, p1, v2}, Llyiahf/vczjk/eq0;->OooOO0O(Llyiahf/vczjk/bq6;Llyiahf/vczjk/ie;)V

    goto :goto_1

    :cond_0
    invoke-static {v8, v9}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, v0, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object p1, p1, Llyiahf/vczjk/lm9;->OooO0O0:Llyiahf/vczjk/rn9;

    invoke-virtual {p1}, Llyiahf/vczjk/rn9;->OooO0O0()J

    move-result-wide v6

    new-instance p1, Llyiahf/vczjk/n21;

    invoke-direct {p1, v6, v7}, Llyiahf/vczjk/n21;-><init>(J)V

    const-wide/16 v10, 0x10

    cmp-long v1, v6, v10

    if-nez v1, :cond_1

    const/4 p1, 0x0

    :cond_1
    if-eqz p1, :cond_2

    iget-wide v6, p1, Llyiahf/vczjk/n21;->OooO00o:J

    goto :goto_0

    :cond_2
    sget-wide v6, Llyiahf/vczjk/n21;->OooO0O0:J

    :goto_0
    invoke-static {v6, v7}, Llyiahf/vczjk/n21;->OooO0Oo(J)F

    move-result p1

    const v1, 0x3e4ccccd    # 0.2f

    mul-float/2addr p1, v1

    invoke-static {p1, v6, v7}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v6

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/ie;->OooOOOo(J)V

    invoke-static {v8, v9}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p1

    invoke-interface {v3, p1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result p1

    invoke-static {v8, v9}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    invoke-interface {v3, v1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result v1

    if-eq p1, v1, :cond_4

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/mm9;->OooO0oo(II)Llyiahf/vczjk/qe;

    move-result-object p1

    invoke-interface {v5, p1, v2}, Llyiahf/vczjk/eq0;->OooOO0O(Llyiahf/vczjk/bq6;Llyiahf/vczjk/ie;)V

    goto :goto_1

    :cond_3
    iget-wide v6, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    if-nez p1, :cond_4

    invoke-virtual {v2, v10, v11}, Llyiahf/vczjk/ie;->OooOOOo(J)V

    iget-wide v6, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p1

    invoke-interface {v3, p1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result p1

    invoke-static {v6, v7}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    invoke-interface {v3, v1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result v1

    if-eq p1, v1, :cond_4

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/mm9;->OooO0oo(II)Llyiahf/vczjk/qe;

    move-result-object p1

    invoke-interface {v5, p1, v2}, Llyiahf/vczjk/eq0;->OooOO0O(Llyiahf/vczjk/bq6;Llyiahf/vczjk/ie;)V

    :cond_4
    :goto_1
    iget-wide v1, v0, Llyiahf/vczjk/mm9;->OooO0OO:J

    const/16 p1, 0x20

    shr-long v3, v1, p1

    long-to-int v3, v3

    int-to-float v3, v3

    iget-object v4, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget v6, v4, Llyiahf/vczjk/lq5;->OooO0Oo:F

    cmpg-float v3, v3, v6

    const/4 v6, 0x1

    const/4 v7, 0x0

    const-wide v8, 0xffffffffL

    if-gez v3, :cond_5

    goto :goto_2

    :cond_5
    iget-boolean v3, v4, Llyiahf/vczjk/lq5;->OooO0OO:Z

    if-nez v3, :cond_7

    and-long v10, v1, v8

    long-to-int v3, v10

    int-to-float v3, v3

    iget v10, v4, Llyiahf/vczjk/lq5;->OooO0o0:F

    cmpg-float v3, v3, v10

    if-gez v3, :cond_6

    goto :goto_2

    :cond_6
    move v3, v7

    goto :goto_3

    :cond_7
    :goto_2
    move v3, v6

    :goto_3
    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    if-eqz v3, :cond_9

    iget v3, v0, Llyiahf/vczjk/lm9;->OooO0o:I

    const/4 v10, 0x3

    if-ne v3, v10, :cond_8

    goto :goto_4

    :cond_8
    move v3, v6

    goto :goto_5

    :cond_9
    :goto_4
    move v3, v7

    :goto_5
    if-eqz v3, :cond_a

    shr-long v6, v1, p1

    long-to-int v6, v6

    int-to-float v6, v6

    and-long/2addr v1, v8

    long-to-int v1, v1

    int-to-float v1, v1

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v6, v2

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    shl-long/2addr v6, p1

    and-long/2addr v1, v8

    or-long/2addr v1, v6

    const-wide/16 v6, 0x0

    invoke-static {v6, v7, v1, v2}, Llyiahf/vczjk/ll6;->OooO0O0(JJ)Llyiahf/vczjk/wj7;

    move-result-object p1

    invoke-interface {v5}, Llyiahf/vczjk/eq0;->OooO0oO()V

    invoke-static {v5, p1}, Llyiahf/vczjk/eq0;->OooOOO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/wj7;)V

    :cond_a
    iget-object p1, v0, Llyiahf/vczjk/lm9;->OooO0O0:Llyiahf/vczjk/rn9;

    iget-object p1, p1, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-object v0, p1, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    iget-object v1, p1, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    if-nez v0, :cond_b

    sget-object v0, Llyiahf/vczjk/vh9;->OooO0O0:Llyiahf/vczjk/vh9;

    :cond_b
    move-object v9, v0

    iget-object v0, p1, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    if-nez v0, :cond_c

    sget-object v0, Llyiahf/vczjk/ij8;->OooO0Oo:Llyiahf/vczjk/ij8;

    :cond_c
    move-object v8, v0

    iget-object p1, p1, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    if-nez p1, :cond_d

    sget-object p1, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;

    :cond_d
    move-object v10, p1

    :try_start_0
    invoke-interface {v1}, Llyiahf/vczjk/kl9;->OooO0OO()Llyiahf/vczjk/ri0;

    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    sget-object p1, Llyiahf/vczjk/hl9;->OooO00o:Llyiahf/vczjk/hl9;

    if-eqz v6, :cond_f

    if-eq v1, p1, :cond_e

    :try_start_1
    invoke-interface {v1}, Llyiahf/vczjk/kl9;->OooO00o()F

    move-result p1

    :goto_6
    move v7, p1

    goto :goto_7

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto :goto_b

    :cond_e
    const/high16 p1, 0x3f800000    # 1.0f

    goto :goto_6

    :goto_7
    invoke-static/range {v4 .. v10}, Llyiahf/vczjk/lq5;->OooOO0(Llyiahf/vczjk/lq5;Llyiahf/vczjk/eq0;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V

    goto :goto_a

    :cond_f
    if-eq v1, p1, :cond_10

    invoke-interface {v1}, Llyiahf/vczjk/kl9;->OooO0O0()J

    move-result-wide v0

    :goto_8
    move-wide v6, v0

    goto :goto_9

    :cond_10
    sget-wide v0, Llyiahf/vczjk/n21;->OooO0O0:J

    goto :goto_8

    :goto_9
    invoke-static/range {v4 .. v10}, Llyiahf/vczjk/lq5;->OooO(Llyiahf/vczjk/lq5;Llyiahf/vczjk/eq0;JLlyiahf/vczjk/ij8;Llyiahf/vczjk/vh9;Llyiahf/vczjk/ig2;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_a
    if-eqz v3, :cond_12

    invoke-interface {v5}, Llyiahf/vczjk/eq0;->OooOOo0()V

    goto :goto_c

    :goto_b
    if-eqz v3, :cond_11

    invoke-interface {v5}, Llyiahf/vczjk/eq0;->OooOOo0()V

    :cond_11
    throw p1

    :cond_12
    :goto_c
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
