.class public abstract Llyiahf/vczjk/ey8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:J

.field public static final OooO0O0:J

.field public static final OooO0OO:J

.field public static final OooO0Oo:Llyiahf/vczjk/kl9;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const/16 v0, 0xe

    invoke-static {v0}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v0

    sput-wide v0, Llyiahf/vczjk/ey8;->OooO00o:J

    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v0

    sput-wide v0, Llyiahf/vczjk/ey8;->OooO0O0:J

    sget-wide v0, Llyiahf/vczjk/n21;->OooO:J

    sput-wide v0, Llyiahf/vczjk/ey8;->OooO0OO:J

    sget-wide v0, Llyiahf/vczjk/n21;->OooO0O0:J

    const-wide/16 v2, 0x10

    cmp-long v2, v0, v2

    if-eqz v2, :cond_0

    new-instance v2, Llyiahf/vczjk/g31;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/g31;-><init>(J)V

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/hl9;->OooO00o:Llyiahf/vczjk/hl9;

    :goto_0
    sput-object v2, Llyiahf/vczjk/ey8;->OooO0Oo:Llyiahf/vczjk/kl9;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/dy8;JLlyiahf/vczjk/ri0;FJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;Llyiahf/vczjk/ox6;Llyiahf/vczjk/ig2;)Llyiahf/vczjk/dy8;
    .locals 24

    move-object/from16 v0, p0

    move-wide/from16 v1, p1

    move-object/from16 v3, p3

    move-wide/from16 v5, p5

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    move-object/from16 v9, p9

    move-object/from16 v10, p10

    move-object/from16 v11, p11

    move-wide/from16 v12, p12

    move-object/from16 v4, p19

    sget-object v16, Llyiahf/vczjk/un9;->OooO0O0:[Llyiahf/vczjk/vn9;

    const-wide v16, 0xff00000000L

    and-long v18, v5, v16

    const-wide/16 v20, 0x0

    cmp-long v18, v18, v20

    if-nez v18, :cond_0

    const/16 v19, 0x1

    goto :goto_0

    :cond_0
    const/16 v19, 0x0

    :goto_0
    const-wide/16 v22, 0x10

    if-nez v19, :cond_5

    iget-wide v14, v0, Llyiahf/vczjk/dy8;->OooO0O0:J

    invoke-static {v5, v6, v14, v15}, Llyiahf/vczjk/un9;->OooO00o(JJ)Z

    move-result v14

    if-eqz v14, :cond_1

    goto :goto_1

    :cond_1
    move-object/from16 v15, p14

    :cond_2
    move-object/from16 v6, p20

    :cond_3
    move-object/from16 v7, p21

    :cond_4
    move-object/from16 v14, p22

    goto/16 :goto_7

    :cond_5
    :goto_1
    if-nez v3, :cond_6

    cmp-long v14, v1, v22

    if-eqz v14, :cond_6

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v14}, Llyiahf/vczjk/kl9;->OooO0O0()J

    move-result-wide v14

    invoke-static {v1, v2, v14, v15}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_6
    if-eqz v8, :cond_7

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO0Oo:Llyiahf/vczjk/cb3;

    invoke-virtual {v8, v14}, Llyiahf/vczjk/cb3;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_7
    if-eqz v7, :cond_8

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO0OO:Llyiahf/vczjk/ib3;

    invoke-virtual {v7, v14}, Llyiahf/vczjk/ib3;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_8
    if-eqz v10, :cond_9

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    if-ne v10, v14, :cond_1

    :cond_9
    and-long v14, v12, v16

    cmp-long v14, v14, v20

    if-nez v14, :cond_a

    goto :goto_2

    :cond_a
    iget-wide v14, v0, Llyiahf/vczjk/dy8;->OooO0oo:J

    invoke-static {v12, v13, v14, v15}, Llyiahf/vczjk/un9;->OooO00o(JJ)Z

    move-result v14

    if-eqz v14, :cond_1

    :goto_2
    if-eqz v4, :cond_b

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    invoke-virtual {v4, v14}, Llyiahf/vczjk/vh9;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_b
    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v14}, Llyiahf/vczjk/kl9;->OooO0OO()Llyiahf/vczjk/ri0;

    move-result-object v14

    invoke-static {v3, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    if-eqz v3, :cond_c

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-interface {v14}, Llyiahf/vczjk/kl9;->OooO00o()F

    move-result v14

    cmpg-float v14, p4, v14

    if-nez v14, :cond_1

    :cond_c
    if-eqz v9, :cond_d

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO0o0:Llyiahf/vczjk/db3;

    invoke-virtual {v9, v14}, Llyiahf/vczjk/db3;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_d
    if-eqz v11, :cond_e

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO0oO:Ljava/lang/String;

    invoke-virtual {v11, v14}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    :cond_e
    if-eqz p14, :cond_f

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooO:Llyiahf/vczjk/f90;

    move-object/from16 v15, p14

    invoke-virtual {v15, v14}, Llyiahf/vczjk/f90;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_2

    goto :goto_3

    :cond_f
    move-object/from16 v15, p14

    :goto_3
    if-eqz p15, :cond_10

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooOO0:Llyiahf/vczjk/ll9;

    move-object/from16 v4, p15

    invoke-virtual {v4, v14}, Llyiahf/vczjk/ll9;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_2

    goto :goto_4

    :cond_10
    move-object/from16 v4, p15

    :goto_4
    if-eqz p16, :cond_11

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooOO0O:Llyiahf/vczjk/e45;

    move-object/from16 v4, p16

    invoke-virtual {v4, v14}, Llyiahf/vczjk/e45;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_2

    :goto_5
    move-wide/from16 v4, p17

    goto :goto_6

    :cond_11
    move-object/from16 v4, p16

    goto :goto_5

    :goto_6
    cmp-long v6, v4, v22

    if-eqz v6, :cond_12

    iget-wide v6, v0, Llyiahf/vczjk/dy8;->OooOO0o:J

    invoke-static {v4, v5, v6, v7}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v6

    if-eqz v6, :cond_2

    :cond_12
    move-object/from16 v6, p20

    if-eqz v6, :cond_13

    iget-object v7, v0, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    invoke-virtual {v6, v7}, Llyiahf/vczjk/ij8;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_3

    :cond_13
    move-object/from16 v7, p21

    if-eqz v7, :cond_14

    iget-object v14, v0, Llyiahf/vczjk/dy8;->OooOOOO:Llyiahf/vczjk/ox6;

    invoke-virtual {v7, v14}, Llyiahf/vczjk/ox6;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_4

    :cond_14
    move-object/from16 v14, p22

    if-eqz v14, :cond_15

    iget-object v4, v0, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    invoke-virtual {v14, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_15

    goto :goto_7

    :cond_15
    return-object v0

    :goto_7
    sget-object v4, Llyiahf/vczjk/hl9;->OooO00o:Llyiahf/vczjk/hl9;

    if-eqz v3, :cond_19

    instance-of v1, v3, Llyiahf/vczjk/gx8;

    if-eqz v1, :cond_17

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/gx8;

    iget-wide v1, v1, Llyiahf/vczjk/gx8;->OooO00o:J

    move/from16 v5, p4

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/fu6;->OooOo0O(FJ)J

    move-result-wide v1

    cmp-long v3, v1, v22

    if-eqz v3, :cond_16

    new-instance v3, Llyiahf/vczjk/g31;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/g31;-><init>(J)V

    goto :goto_8

    :cond_16
    move-object v3, v4

    goto :goto_8

    :cond_17
    move/from16 v5, p4

    instance-of v1, v3, Llyiahf/vczjk/fj8;

    if-eqz v1, :cond_18

    new-instance v1, Llyiahf/vczjk/ti0;

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/fj8;

    invoke-direct {v1, v2, v5}, Llyiahf/vczjk/ti0;-><init>(Llyiahf/vczjk/fj8;F)V

    move-object v3, v1

    goto :goto_8

    :cond_18
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_19
    cmp-long v3, v1, v22

    if-eqz v3, :cond_16

    new-instance v3, Llyiahf/vczjk/g31;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/g31;-><init>(J)V

    :goto_8
    iget-object v1, v0, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v2, v3, Llyiahf/vczjk/ti0;

    if-eqz v2, :cond_1b

    instance-of v5, v1, Llyiahf/vczjk/ti0;

    if-eqz v5, :cond_1b

    new-instance v2, Llyiahf/vczjk/ti0;

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/ti0;

    check-cast v3, Llyiahf/vczjk/ti0;

    new-instance v5, Llyiahf/vczjk/il9;

    invoke-direct {v5, v1}, Llyiahf/vczjk/il9;-><init>(Llyiahf/vczjk/kl9;)V

    iget v1, v3, Llyiahf/vczjk/ti0;->OooO0O0:F

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-eqz v3, :cond_1a

    invoke-virtual {v5}, Llyiahf/vczjk/il9;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    :cond_1a
    iget-object v3, v4, Llyiahf/vczjk/ti0;->OooO00o:Llyiahf/vczjk/fj8;

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/ti0;-><init>(Llyiahf/vczjk/fj8;F)V

    move-object v3, v2

    goto :goto_9

    :cond_1b
    if-eqz v2, :cond_1c

    instance-of v5, v1, Llyiahf/vczjk/ti0;

    if-nez v5, :cond_1c

    goto :goto_9

    :cond_1c
    if-nez v2, :cond_1d

    instance-of v2, v1, Llyiahf/vczjk/ti0;

    if-eqz v2, :cond_1d

    move-object v3, v1

    goto :goto_9

    :cond_1d
    new-instance v2, Llyiahf/vczjk/jl9;

    invoke-direct {v2, v1}, Llyiahf/vczjk/jl9;-><init>(Llyiahf/vczjk/kl9;)V

    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1e

    goto :goto_9

    :cond_1e
    invoke-virtual {v2}, Llyiahf/vczjk/jl9;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/kl9;

    :goto_9
    if-nez v10, :cond_1f

    iget-object v1, v0, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    move-object v10, v1

    :cond_1f
    if-nez v18, :cond_20

    iget-wide v1, v0, Llyiahf/vczjk/dy8;->OooO0O0:J

    goto :goto_a

    :cond_20
    move-wide/from16 v1, p5

    :goto_a
    if-nez p7, :cond_21

    iget-object v4, v0, Llyiahf/vczjk/dy8;->OooO0OO:Llyiahf/vczjk/ib3;

    goto :goto_b

    :cond_21
    move-object/from16 v4, p7

    :goto_b
    if-nez v8, :cond_22

    iget-object v5, v0, Llyiahf/vczjk/dy8;->OooO0Oo:Llyiahf/vczjk/cb3;

    goto :goto_c

    :cond_22
    move-object v5, v8

    :goto_c
    if-nez v9, :cond_23

    iget-object v8, v0, Llyiahf/vczjk/dy8;->OooO0o0:Llyiahf/vczjk/db3;

    move-object v9, v8

    :cond_23
    if-nez v11, :cond_24

    iget-object v8, v0, Llyiahf/vczjk/dy8;->OooO0oO:Ljava/lang/String;

    move-object v11, v8

    :cond_24
    and-long v16, v12, v16

    cmp-long v8, v16, v20

    if-nez v8, :cond_25

    iget-wide v12, v0, Llyiahf/vczjk/dy8;->OooO0oo:J

    :cond_25
    if-nez v15, :cond_26

    iget-object v8, v0, Llyiahf/vczjk/dy8;->OooO:Llyiahf/vczjk/f90;

    move-object v15, v8

    :cond_26
    if-nez p15, :cond_27

    iget-object v8, v0, Llyiahf/vczjk/dy8;->OooOO0:Llyiahf/vczjk/ll9;

    goto :goto_d

    :cond_27
    move-object/from16 v8, p15

    :goto_d
    move-wide/from16 p2, v1

    if-nez p16, :cond_28

    iget-object v1, v0, Llyiahf/vczjk/dy8;->OooOO0O:Llyiahf/vczjk/e45;

    goto :goto_e

    :cond_28
    move-object/from16 v1, p16

    :goto_e
    cmp-long v2, p17, v22

    if-eqz v2, :cond_29

    move-object/from16 p13, v1

    move-wide/from16 v1, p17

    goto :goto_f

    :cond_29
    move-object/from16 p13, v1

    iget-wide v1, v0, Llyiahf/vczjk/dy8;->OooOO0o:J

    :goto_f
    move-wide/from16 p14, v1

    if-nez p19, :cond_2a

    iget-object v1, v0, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    goto :goto_10

    :cond_2a
    move-object/from16 v1, p19

    :goto_10
    if-nez v6, :cond_2b

    iget-object v2, v0, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    goto :goto_11

    :cond_2b
    move-object v2, v6

    :goto_11
    iget-object v6, v0, Llyiahf/vczjk/dy8;->OooOOOO:Llyiahf/vczjk/ox6;

    if-nez v6, :cond_2c

    move-object v6, v7

    :cond_2c
    if-nez v14, :cond_2d

    iget-object v0, v0, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    move-object v14, v0

    :cond_2d
    new-instance v0, Llyiahf/vczjk/dy8;

    move-object/from16 p0, v0

    move-object/from16 p16, v1

    move-object/from16 p17, v2

    move-object/from16 p1, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p18, v6

    move-object/from16 p12, v8

    move-object/from16 p6, v9

    move-object/from16 p7, v10

    move-object/from16 p8, v11

    move-wide/from16 p9, v12

    move-object/from16 p19, v14

    move-object/from16 p11, v15

    invoke-direct/range {p0 .. p19}, Llyiahf/vczjk/dy8;-><init>(Llyiahf/vczjk/kl9;JLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;Llyiahf/vczjk/ox6;Llyiahf/vczjk/ig2;)V

    return-object v0
.end method

.method public static final OooO0O0(FLjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    float-to-double v0, p0

    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    cmpg-double p0, v0, v2

    if-gez p0, :cond_0

    return-object p1

    :cond_0
    return-object p2
.end method

.method public static final OooO0OO(JJF)J
    .locals 7

    sget-object v0, Llyiahf/vczjk/un9;->OooO0O0:[Llyiahf/vczjk/vn9;

    const-wide v0, 0xff00000000L

    and-long v2, p0, v0

    const-wide/16 v4, 0x0

    cmp-long v6, v2, v4

    if-nez v6, :cond_0

    goto :goto_0

    :cond_0
    and-long/2addr v0, p2

    cmp-long v0, v0, v4

    if-nez v0, :cond_1

    :goto_0
    new-instance v0, Llyiahf/vczjk/un9;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/un9;-><init>(J)V

    new-instance p0, Llyiahf/vczjk/un9;

    invoke-direct {p0, p2, p3}, Llyiahf/vczjk/un9;-><init>(J)V

    invoke-static {p4, v0, p0}, Llyiahf/vczjk/ey8;->OooO0O0(FLjava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/un9;

    iget-wide p0, p0, Llyiahf/vczjk/un9;->OooO00o:J

    return-wide p0

    :cond_1
    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/eo6;->OooO0oO(JJ)V

    invoke-static {p0, p1}, Llyiahf/vczjk/un9;->OooO0OO(J)F

    move-result p0

    invoke-static {p2, p3}, Llyiahf/vczjk/un9;->OooO0OO(J)F

    move-result p1

    invoke-static {p0, p1, p4}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p0

    invoke-static {p0, v2, v3}, Llyiahf/vczjk/eo6;->OooOo0(FJ)J

    move-result-wide p0

    return-wide p0
.end method
