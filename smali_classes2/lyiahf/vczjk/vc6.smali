.class public abstract Llyiahf/vczjk/vc6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:[F

.field public static final OooO0O0:Llyiahf/vczjk/c60;

.field public static final OooO0OO:Llyiahf/vczjk/mm3;

.field public static final synthetic OooO0Oo:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    const/16 v0, 0x5b

    new-array v0, v0, [F

    sput-object v0, Llyiahf/vczjk/vc6;->OooO00o:[F

    new-instance v0, Llyiahf/vczjk/c60;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/c60;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/vc6;->OooO0O0:Llyiahf/vczjk/c60;

    new-instance v0, Llyiahf/vczjk/mm3;

    const-string v1, "InvalidModuleNotifier"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/mm3;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/vc6;->OooO0OO:Llyiahf/vczjk/mm3;

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/xl;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v3, p1

    move-object/from16 v0, p5

    instance-of v1, v0, Llyiahf/vczjk/wa9;

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/wa9;

    iget v2, v1, Llyiahf/vczjk/wa9;->label:I

    const/high16 v4, -0x80000000

    and-int v5, v2, v4

    if-eqz v5, :cond_0

    sub-int/2addr v2, v4

    iput v2, v1, Llyiahf/vczjk/wa9;->label:I

    :goto_0
    move-object v8, v1

    goto :goto_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/wa9;

    invoke-direct {v1, v0}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    goto :goto_0

    :goto_1
    iget-object v0, v8, Llyiahf/vczjk/wa9;->result:Ljava/lang/Object;

    sget-object v9, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, v8, Llyiahf/vczjk/wa9;->label:I

    const/4 v10, 0x2

    const/4 v11, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v11, :cond_2

    if-ne v1, v10, :cond_1

    iget-object v1, v8, Llyiahf/vczjk/wa9;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/hl7;

    iget-object v2, v8, Llyiahf/vczjk/wa9;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object v3, v8, Llyiahf/vczjk/wa9;->L$1:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/yk;

    iget-object v4, v8, Llyiahf/vczjk/wa9;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xl;

    :goto_2
    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_8

    :catch_0
    move-exception v0

    goto/16 :goto_b

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    iget-object v1, v8, Llyiahf/vczjk/wa9;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/hl7;

    iget-object v2, v8, Llyiahf/vczjk/wa9;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object v3, v8, Llyiahf/vczjk/wa9;->L$1:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/yk;

    iget-object v4, v8, Llyiahf/vczjk/wa9;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xl;

    goto :goto_2

    :cond_3
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    const-wide/16 v0, 0x0

    invoke-interface {v3, v0, v1}, Llyiahf/vczjk/yk;->OooO0o(J)Ljava/lang/Object;

    move-result-object v13

    invoke-interface {v3, v0, v1}, Llyiahf/vczjk/yk;->OooO0Oo(J)Llyiahf/vczjk/dm;

    move-result-object v15

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const-wide/high16 v4, -0x8000000000000000L

    cmp-long v0, p2, v4

    if-nez v0, :cond_6

    :try_start_1
    invoke-interface {v8}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoOO(Llyiahf/vczjk/or1;)F

    move-result v6

    new-instance v0, Llyiahf/vczjk/ya9;
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_3

    move-object/from16 v5, p0

    move-object/from16 v7, p4

    move-object v2, v13

    move-object v4, v15

    :try_start_2
    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/ya9;-><init>(Llyiahf/vczjk/hl7;Ljava/lang/Object;Llyiahf/vczjk/yk;Llyiahf/vczjk/dm;Llyiahf/vczjk/xl;FLlyiahf/vczjk/oe3;)V
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_2

    move-object v7, v1

    :try_start_3
    iput-object v5, v8, Llyiahf/vczjk/wa9;->L$0:Ljava/lang/Object;

    iput-object v3, v8, Llyiahf/vczjk/wa9;->L$1:Ljava/lang/Object;

    move-object/from16 v6, p4

    iput-object v6, v8, Llyiahf/vczjk/wa9;->L$2:Ljava/lang/Object;

    iput-object v7, v8, Llyiahf/vczjk/wa9;->L$3:Ljava/lang/Object;

    iput v11, v8, Llyiahf/vczjk/wa9;->label:I

    invoke-interface {v3}, Llyiahf/vczjk/yk;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-static {v0, v8}, Llyiahf/vczjk/sb;->OoooOOo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_3

    :cond_4
    new-instance v1, Llyiahf/vczjk/bb9;

    invoke-direct {v1, v0}, Llyiahf/vczjk/bb9;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {v8}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v0

    invoke-interface {v0, v8, v1}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object v0
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_1

    :goto_3
    if-ne v0, v9, :cond_5

    goto/16 :goto_a

    :cond_5
    move-object v4, v5

    move-object v2, v6

    goto :goto_7

    :goto_4
    move-object v4, v5

    :goto_5
    move-object v1, v7

    goto/16 :goto_b

    :catch_1
    move-exception v0

    goto :goto_4

    :catch_2
    move-exception v0

    :goto_6
    move-object v7, v1

    move-object v4, v5

    goto/16 :goto_b

    :catch_3
    move-exception v0

    move-object/from16 v5, p0

    goto :goto_6

    :cond_6
    move-object/from16 v5, p0

    move-object/from16 v6, p4

    move-object v7, v1

    :try_start_4
    new-instance v12, Llyiahf/vczjk/fl;

    invoke-interface {v3}, Llyiahf/vczjk/yk;->OooO0OO()Llyiahf/vczjk/m1a;

    move-result-object v14

    invoke-interface {v3}, Llyiahf/vczjk/yk;->OooO0oO()Ljava/lang/Object;

    move-result-object v18

    new-instance v0, Llyiahf/vczjk/za9;

    invoke-direct {v0, v5}, Llyiahf/vczjk/za9;-><init>(Llyiahf/vczjk/xl;)V

    move-wide/from16 v19, p2

    move-wide/from16 v16, p2

    move-object/from16 v21, v0

    invoke-direct/range {v12 .. v21}, Llyiahf/vczjk/fl;-><init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/dm;JLjava/lang/Object;JLlyiahf/vczjk/le3;)V

    invoke-interface {v8}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoOO(Llyiahf/vczjk/or1;)F

    move-result v0

    move-wide/from16 v1, p2

    move-object v4, v3

    move v3, v0

    move-object v0, v12

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/vc6;->OooOOo(Llyiahf/vczjk/fl;JFLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V

    move-object v12, v0

    iput-object v12, v7, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;
    :try_end_4
    .catch Ljava/util/concurrent/CancellationException; {:try_start_4 .. :try_end_4} :catch_5

    move-object/from16 v4, p0

    move-object/from16 v3, p1

    move-object/from16 v2, p4

    :goto_7
    move-object v1, v7

    :cond_7
    :goto_8
    :try_start_5
    iget-object v0, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v0, Llyiahf/vczjk/fl;

    iget-object v0, v0, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-interface {v8}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoOO(Llyiahf/vczjk/or1;)F

    move-result v0

    new-instance v5, Llyiahf/vczjk/ab9;
    :try_end_5
    .catch Ljava/util/concurrent/CancellationException; {:try_start_5 .. :try_end_5} :catch_0

    move/from16 p2, v0

    move-object/from16 p1, v1

    move-object/from16 p5, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p0, v5

    :try_start_6
    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/ab9;-><init>(Llyiahf/vczjk/hl7;FLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V
    :try_end_6
    .catch Ljava/util/concurrent/CancellationException; {:try_start_6 .. :try_end_6} :catch_4

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v3, p3

    move-object/from16 v4, p4

    move-object/from16 v2, p5

    :try_start_7
    iput-object v4, v8, Llyiahf/vczjk/wa9;->L$0:Ljava/lang/Object;

    iput-object v3, v8, Llyiahf/vczjk/wa9;->L$1:Ljava/lang/Object;

    iput-object v2, v8, Llyiahf/vczjk/wa9;->L$2:Ljava/lang/Object;

    iput-object v1, v8, Llyiahf/vczjk/wa9;->L$3:Ljava/lang/Object;

    iput v10, v8, Llyiahf/vczjk/wa9;->label:I

    invoke-interface {v3}, Llyiahf/vczjk/yk;->OooO00o()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-static {v0, v8}, Llyiahf/vczjk/sb;->OoooOOo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_9

    :cond_8
    new-instance v5, Llyiahf/vczjk/bb9;

    invoke-direct {v5, v0}, Llyiahf/vczjk/bb9;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {v8}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v0

    invoke-interface {v0, v8, v5}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object v0
    :try_end_7
    .catch Ljava/util/concurrent/CancellationException; {:try_start_7 .. :try_end_7} :catch_0

    :goto_9
    if-ne v0, v9, :cond_7

    :goto_a
    return-object v9

    :catch_4
    move-exception v0

    move-object/from16 v1, p1

    move-object/from16 v4, p4

    goto :goto_b

    :cond_9
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :catch_5
    move-exception v0

    move-object/from16 v4, p0

    goto/16 :goto_5

    :goto_b
    iget-object v2, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/fl;

    if-nez v2, :cond_a

    goto :goto_c

    :cond_a
    iget-object v2, v2, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :goto_c
    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/fl;

    if-eqz v1, :cond_b

    iget-wide v1, v1, Llyiahf/vczjk/fl;->OooO0oO:J

    iget-wide v5, v4, Llyiahf/vczjk/xl;->OooOOOo:J

    cmp-long v1, v1, v5

    if-nez v1, :cond_b

    const/4 v1, 0x0

    iput-boolean v1, v4, Llyiahf/vczjk/xl;->OooOOo:Z

    :cond_b
    throw v0
.end method

.method public static final OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/lg0;FFLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;JJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 26

    move-object/from16 v2, p1

    move/from16 v0, p22

    const/4 v1, 0x1

    move-object/from16 v3, p21

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, 0x36d73cd8

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v4, v0, 0x6

    if-nez v4, :cond_1

    move-object/from16 v4, p0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v0

    goto :goto_1

    :cond_1
    move-object/from16 v4, p0

    move v5, v0

    :goto_1
    and-int/lit8 v6, v0, 0x30

    if-nez v6, :cond_3

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x20

    goto :goto_2

    :cond_2
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v5, v6

    :cond_3
    and-int/lit16 v6, v0, 0x180

    if-nez v6, :cond_5

    move-object/from16 v6, p2

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x100

    goto :goto_3

    :cond_4
    const/16 v7, 0x80

    :goto_3
    or-int/2addr v5, v7

    goto :goto_4

    :cond_5
    move-object/from16 v6, p2

    :goto_4
    and-int/lit16 v7, v0, 0xc00

    move/from16 v9, p3

    if-nez v7, :cond_7

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v7

    if-eqz v7, :cond_6

    const/16 v7, 0x800

    goto :goto_5

    :cond_6
    const/16 v7, 0x400

    :goto_5
    or-int/2addr v5, v7

    :cond_7
    or-int/lit16 v7, v5, 0x6000

    const/high16 v8, 0x30000

    and-int/2addr v8, v0

    if-nez v8, :cond_8

    const v7, 0x16000

    or-int/2addr v7, v5

    :cond_8
    const/high16 v5, 0x180000

    and-int/2addr v5, v0

    if-nez v5, :cond_9

    const/high16 v5, 0x80000

    or-int/2addr v7, v5

    :cond_9
    const/high16 v5, 0xc00000

    and-int/2addr v5, v0

    if-nez v5, :cond_a

    const/high16 v5, 0x400000

    or-int/2addr v7, v5

    :cond_a
    const/high16 v5, 0x36000000

    or-int/2addr v5, v7

    const v7, 0x12492493

    and-int/2addr v7, v5

    const v8, 0x12492492

    const/4 v10, 0x0

    if-ne v7, v8, :cond_b

    move v7, v10

    goto :goto_6

    :cond_b
    move v7, v1

    :goto_6
    and-int/2addr v5, v1

    invoke-virtual {v3, v5, v7}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v5

    if-eqz v5, :cond_11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v5, v0, 0x1

    if-eqz v5, :cond_d

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v5

    if-eqz v5, :cond_c

    goto :goto_7

    :cond_c
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v10, p4

    move-object/from16 v12, p5

    move-wide/from16 v13, p6

    move-wide/from16 v15, p8

    move/from16 v17, p10

    move/from16 v18, p11

    move-object/from16 v19, p12

    move/from16 v11, p13

    move-object/from16 v21, p15

    move-wide/from16 v7, p16

    move-wide/from16 v0, p18

    goto :goto_8

    :cond_d
    :goto_7
    sget v5, Llyiahf/vczjk/nf0;->OooO0OO:F

    sget-object v7, Llyiahf/vczjk/nf0;->OooO00o:Llyiahf/vczjk/nf0;

    sget-object v7, Llyiahf/vczjk/sl8;->OooO0O0:Llyiahf/vczjk/dk8;

    invoke-static {v7, v3}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/sl8;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v8, v3}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v11

    invoke-static {v11, v12, v3}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide v13

    int-to-float v8, v10

    sget v15, Llyiahf/vczjk/nf0;->OooO0O0:F

    sget-object v16, Llyiahf/vczjk/u91;->OooO00o:Llyiahf/vczjk/a91;

    sget-object v17, Llyiahf/vczjk/u91;->OooO0O0:Llyiahf/vczjk/a91;

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    move-wide/from16 p4, v11

    iget-wide v10, v1, Llyiahf/vczjk/x21;->OooOOOo:J

    invoke-static {v10, v11, v3}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide v18

    move-object v12, v7

    move-object/from16 v21, v17

    move-wide/from16 v0, v18

    move/from16 v17, v8

    move-wide v7, v10

    move/from16 v18, v15

    move-object/from16 v19, v16

    const/4 v11, 0x1

    move v10, v5

    move-wide v15, v13

    move-wide/from16 v13, p4

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v5, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v2, v5}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v2, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v5, v7, v8, v2}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v4, 0x0

    invoke-static {v5, v4}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v3, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v20, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v20 .. v20}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-wide/from16 p4, v7

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_e

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_e
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v3, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_f

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_10

    :cond_f
    invoke-static {v5, v3, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v4, Llyiahf/vczjk/n21;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    new-instance v5, Llyiahf/vczjk/yf0;

    move-object/from16 v20, p0

    move-object/from16 v6, p2

    move-wide/from16 v23, p4

    move-object/from16 v7, p14

    move-object/from16 v8, p20

    invoke-direct/range {v5 .. v21}, Llyiahf/vczjk/yf0;-><init>(Llyiahf/vczjk/lg0;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FFZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;)V

    const v4, 0x3b982e1e

    invoke-static {v4, v5, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v5, 0x38

    invoke-static {v2, v4, v3, v5}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    const/4 v2, 0x1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move v5, v10

    move-object v6, v12

    move-wide v7, v13

    move-wide v9, v15

    move/from16 v12, v18

    move-object/from16 v13, v19

    move-object/from16 v16, v21

    move-wide/from16 v19, v0

    move v14, v11

    move/from16 v11, v17

    move-wide/from16 v17, v23

    goto :goto_a

    :cond_11
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v5, p4

    move-object/from16 v6, p5

    move-wide/from16 v7, p6

    move-wide/from16 v9, p8

    move/from16 v11, p10

    move/from16 v12, p11

    move-object/from16 v13, p12

    move/from16 v14, p13

    move-object/from16 v16, p15

    move-wide/from16 v17, p16

    move-wide/from16 v19, p18

    :goto_a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_12

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/rf0;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v15, p14

    move-object/from16 v21, p20

    move/from16 v22, p22

    move-object/from16 v25, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v22}, Llyiahf/vczjk/rf0;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/lg0;FFLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;JJLlyiahf/vczjk/a91;I)V

    move-object/from16 v1, v25

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/zl8;Llyiahf/vczjk/rf1;I)V
    .locals 12

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    const/4 v0, 0x0

    const/4 v1, 0x2

    const/4 v2, 0x4

    const/4 v3, 0x1

    move-object/from16 v4, p6

    check-cast v4, Llyiahf/vczjk/zf1;

    const v7, -0x4894fcb7

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    move v7, v2

    goto :goto_0

    :cond_0
    move v7, v1

    :goto_0
    or-int v7, p7, v7

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    const/16 v9, 0x4000

    if-eqz v8, :cond_1

    move v8, v9

    goto :goto_1

    :cond_1
    const/16 v8, 0x2000

    :goto_1
    or-int/2addr v7, v8

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    const/high16 v10, 0x20000

    if-eqz v8, :cond_2

    move v8, v10

    goto :goto_2

    :cond_2
    const/high16 v8, 0x10000

    :goto_2
    or-int/2addr v7, v8

    const v8, 0x12493

    and-int/2addr v8, v7

    const v11, 0x12492

    if-eq v8, v11, :cond_3

    move v8, v3

    goto :goto_3

    :cond_3
    move v8, v0

    :goto_3
    and-int/lit8 v11, v7, 0x1

    invoke-virtual {v4, v11, v8}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v8

    if-eqz v8, :cond_e

    if-nez p0, :cond_4

    sget-object v8, Llyiahf/vczjk/u91;->OooO0OO:Llyiahf/vczjk/a91;

    goto :goto_4

    :cond_4
    move-object v8, p0

    :goto_4
    new-array v2, v2, [Llyiahf/vczjk/ze3;

    aput-object v8, v2, v0

    aput-object p1, v2, v3

    aput-object p2, v2, v1

    const/4 v1, 0x3

    aput-object p3, v2, v1

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    const/high16 v2, 0x70000

    and-int/2addr v2, v7

    if-ne v2, v10, :cond_5

    move v2, v3

    goto :goto_5

    :cond_5
    move v2, v0

    :goto_5
    const v8, 0xe000

    and-int/2addr v7, v8

    if-ne v7, v9, :cond_6

    move v7, v3

    goto :goto_6

    :cond_6
    move v7, v0

    :goto_6
    or-int/2addr v2, v7

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v2, :cond_7

    if-ne v7, v8, :cond_8

    :cond_7
    new-instance v7, Llyiahf/vczjk/ag0;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/ag0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/le3;)V

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/zp5;

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    new-instance v9, Llyiahf/vczjk/do4;

    invoke-direct {v9, v1}, Llyiahf/vczjk/do4;-><init>(Ljava/util/List;)V

    new-instance v1, Llyiahf/vczjk/a91;

    const v10, -0x74725ab7

    invoke-direct {v1, v10, v9, v3}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_9

    if-ne v10, v8, :cond_a

    :cond_9
    new-instance v10, Llyiahf/vczjk/aq5;

    invoke-direct {v10, v7}, Llyiahf/vczjk/aq5;-><init>(Llyiahf/vczjk/zp5;)V

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v10, Llyiahf/vczjk/lf5;

    iget v7, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v4, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_b

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_b
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_c

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_d

    :cond_c
    invoke-static {v7, v4, v7, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v4, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v1, v4, v0}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_8

    :cond_e
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_f

    new-instance v0, Llyiahf/vczjk/f60;

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/f60;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/zl8;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 4

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x3799f46e

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p3, 0x6

    if-nez v0, :cond_1

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p3

    goto :goto_1

    :cond_1
    move v0, p3

    :goto_1
    and-int/lit8 v1, p3, 0x30

    if-nez v1, :cond_3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit8 v1, v0, 0x13

    const/16 v2, 0x12

    const/4 v3, 0x1

    if-eq v1, v2, :cond_4

    move v1, v3

    goto :goto_3

    :cond_4
    const/4 v1, 0x0

    :goto_3
    and-int/2addr v0, v3

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-static {p0, p1}, Landroidx/compose/ui/draw/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {p2, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_4

    :cond_5
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_6

    new-instance v0, Llyiahf/vczjk/iq0;

    invoke-direct {v0, p0, p1, p3}, Llyiahf/vczjk/iq0;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static final OooO0Oo(FFIJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 8

    check-cast p6, Llyiahf/vczjk/zf1;

    const v0, -0x68e56267    # -4.9959E-25f

    invoke-virtual {p6, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p6, p3, p4}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    if-eqz v0, :cond_0

    const/16 v0, 0x800

    goto :goto_0

    :cond_0
    const/16 v0, 0x400

    :goto_0
    or-int/2addr v0, p2

    or-int/lit16 v0, v0, 0x6000

    const v1, 0x12493

    and-int/2addr v0, v1

    const v1, 0x12492

    if-ne v0, v1, :cond_2

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_2
    :goto_1
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, p2, 0x1

    if-eqz v0, :cond_4

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_4
    :goto_2
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-static {p7, p0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v0, v1}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v2, 0x4c5de2

    invoke-virtual {p6, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v3, :cond_5

    new-instance v2, Llyiahf/vczjk/oOOO0OO0;

    const/16 v3, 0xd

    invoke-direct {v2, v3}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {p6, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    invoke-virtual {p6, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x7

    const/4 v5, 0x0

    invoke-static {v1, v3, v5, v2, v4}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v0, v1, v3}, Llyiahf/vczjk/ye5;->Oooo0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Z)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v0, p3, p4, v1}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v0, p1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v3, 0x36

    invoke-static {v1, v2, p6, v3}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v1

    iget v2, p6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p6, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, p6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_6

    invoke-virtual {p6, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_6
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, p6, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p6, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, p6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_7

    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_8

    :cond_7
    invoke-static {v2, p6, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, p6, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p6, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v1, v1, Llyiahf/vczjk/x21;->OooOOoo:J

    new-instance v3, Llyiahf/vczjk/n21;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/e4;

    const/4 v2, 0x3

    invoke-direct {v1, p5, v2}, Llyiahf/vczjk/e4;-><init>(Llyiahf/vczjk/a91;I)V

    const v2, 0x58851e23

    invoke-static {v2, v1, p6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const/16 v2, 0x38

    invoke-static {v0, v1, p6, v2}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    const/4 v0, 0x1

    invoke-virtual {p6, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    invoke-virtual {p6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p6

    if-eqz p6, :cond_9

    new-instance v0, Llyiahf/vczjk/j31;

    move v2, p0

    move v3, p1

    move v7, p2

    move-wide v4, p3

    move-object v6, p5

    move-object v1, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/j31;-><init>(Llyiahf/vczjk/kl5;FFJLlyiahf/vczjk/a91;I)V

    iput-object v0, p6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_9
    return-void
.end method

.method public static final OooO0o(Llyiahf/vczjk/zl8;FFZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 23

    move-object/from16 v1, p0

    move/from16 v6, p1

    move/from16 v7, p2

    move/from16 v8, p3

    move-object/from16 v11, p13

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, -0x7db27d14

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p14, v0

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x20

    goto :goto_1

    :cond_1
    const/16 v3, 0x10

    :goto_1
    or-int/2addr v0, v3

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-eqz v3, :cond_2

    const/16 v3, 0x100

    goto :goto_2

    :cond_2
    const/16 v3, 0x80

    :goto_2
    or-int/2addr v0, v3

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    if-eqz v3, :cond_3

    const/16 v3, 0x800

    goto :goto_3

    :cond_3
    const/16 v3, 0x400

    :goto_3
    or-int/2addr v0, v3

    move-object/from16 v13, p4

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_4

    const/16 v3, 0x4000

    goto :goto_4

    :cond_4
    const/16 v3, 0x2000

    :goto_4
    or-int/2addr v0, v3

    move-wide/from16 v14, p5

    invoke-virtual {v11, v14, v15}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v3

    if-eqz v3, :cond_5

    const/high16 v3, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v3, 0x10000

    :goto_5
    or-int/2addr v0, v3

    move-wide/from16 v3, p7

    invoke-virtual {v11, v3, v4}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v5

    if-eqz v5, :cond_6

    const/high16 v5, 0x100000

    goto :goto_6

    :cond_6
    const/high16 v5, 0x80000

    :goto_6
    or-int/2addr v0, v5

    move/from16 v5, p9

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v16

    if-eqz v16, :cond_7

    const/high16 v16, 0x800000

    goto :goto_7

    :cond_7
    const/high16 v16, 0x400000

    :goto_7
    or-int v0, v0, v16

    move/from16 v10, p10

    const/16 v16, 0x1

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v17

    if-eqz v17, :cond_8

    const/high16 v17, 0x4000000

    goto :goto_8

    :cond_8
    const/high16 v17, 0x2000000

    :goto_8
    or-int v0, v0, v17

    move-object/from16 v9, p11

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_9

    const/high16 v18, 0x20000000

    goto :goto_9

    :cond_9
    const/high16 v18, 0x10000000

    :goto_9
    or-int v18, v0, v18

    move-object/from16 v0, p12

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_a

    const/16 v19, 0x4

    goto :goto_a

    :cond_a
    const/16 v19, 0x2

    :goto_a
    const v20, 0x12492493

    and-int v12, v18, v20

    const v2, 0x12492492

    if-ne v12, v2, :cond_c

    and-int/lit8 v2, v19, 0x3

    const/4 v12, 0x2

    if-eq v2, v12, :cond_b

    goto :goto_b

    :cond_b
    const/4 v2, 0x0

    goto :goto_c

    :cond_c
    :goto_b
    move/from16 v2, v16

    :goto_c
    and-int/lit8 v12, v18, 0x1

    invoke-virtual {v11, v12, v2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_17

    sget-object v2, Llyiahf/vczjk/zo5;->OooOOO0:Llyiahf/vczjk/zo5;

    invoke-static {v2, v11}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v4

    invoke-static {v2, v11}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/zo5;->OooOOOo:Llyiahf/vczjk/zo5;

    invoke-static {v3, v11}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v3

    and-int/lit8 v12, v18, 0xe

    const/4 v0, 0x4

    if-ne v12, v0, :cond_d

    move/from16 v0, v16

    goto :goto_d

    :cond_d
    const/4 v0, 0x0

    :goto_d
    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v0, v0, v19

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v0, v0, v19

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v0, v0, v19

    move/from16 v19, v0

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v19, :cond_f

    if-ne v0, v5, :cond_e

    goto :goto_e

    :cond_e
    move-object v8, v5

    goto :goto_f

    :cond_f
    :goto_e
    new-instance v0, Llyiahf/vczjk/sf0;

    move-object/from16 v19, v5

    const/4 v5, 0x0

    move-object/from16 v8, v19

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/sf0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/p13;Llyiahf/vczjk/p13;Llyiahf/vczjk/p13;I)V

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_f
    check-cast v0, Llyiahf/vczjk/le3;

    invoke-static {v0, v11}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v8, :cond_10

    invoke-static {v11}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v0

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v0, Llyiahf/vczjk/xr1;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    sget-object v3, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/f62;

    invoke-interface {v3, v6}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v3

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz p3, :cond_13

    const v5, 0x7a2835e3

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v1, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    move-object/from16 v19, v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v5, :cond_11

    if-ne v2, v8, :cond_12

    :cond_11
    new-instance v2, Llyiahf/vczjk/o0OO000o;

    const/16 v5, 0x8

    invoke-direct {v2, v5, v0, v1}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    sget v5, Llyiahf/vczjk/wl8;->OooO00o:F

    new-instance v5, Llyiahf/vczjk/vl8;

    invoke-direct {v5, v1, v2}, Llyiahf/vczjk/vl8;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v2, v5

    :cond_12
    check-cast v2, Llyiahf/vczjk/bz5;

    const/4 v5, 0x0

    invoke-static {v4, v2, v5}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v5, 0x0

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_10

    :cond_13
    move-object/from16 v19, v2

    const/4 v5, 0x0

    const v2, 0x7a2e39d6

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v2, v4

    :goto_10
    const/4 v5, 0x0

    move-object/from16 v20, v0

    move/from16 v0, v16

    invoke-static {v4, v5, v7, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOo(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-interface {v4, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v4, v1, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    const/4 v5, 0x4

    if-ne v12, v5, :cond_14

    goto :goto_11

    :cond_14
    const/4 v0, 0x0

    :goto_11
    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v5

    or-int/2addr v0, v5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_15

    if-ne v5, v8, :cond_16

    :cond_15
    new-instance v5, Llyiahf/vczjk/tf0;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/tf0;-><init>(Llyiahf/vczjk/zl8;F)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v5, Llyiahf/vczjk/ze3;

    invoke-static {v2, v4, v5}, Landroidx/compose/material3/internal/OooO0O0;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/c9;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    move-object v2, v1

    iget-object v1, v2, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    const/4 v4, 0x0

    const/16 v5, 0x18

    move/from16 v3, p3

    move-object v8, v2

    move-object/from16 v2, v19

    invoke-static/range {v0 .. v5}, Landroidx/compose/material3/internal/OooO0O0;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/c9;Llyiahf/vczjk/nf6;ZZI)Llyiahf/vczjk/kl5;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vf0;

    const/4 v5, 0x0

    invoke-direct {v1, v8, v5}, Llyiahf/vczjk/vf0;-><init>(Llyiahf/vczjk/zl8;I)V

    invoke-static {v0, v1}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v12

    new-instance v0, Llyiahf/vczjk/jg0;

    move/from16 v4, p3

    move-object/from16 v5, p12

    move-object v1, v8

    move-object v2, v9

    move-object/from16 v3, v20

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/jg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/a91;Llyiahf/vczjk/xr1;ZLlyiahf/vczjk/a91;)V

    const v1, 0x59e70371

    invoke-static {v1, v0, v11}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v19

    shr-int/lit8 v0, v18, 0x9

    and-int/lit8 v1, v0, 0x70

    const/high16 v2, 0xc00000

    or-int/2addr v1, v2

    and-int/lit16 v2, v0, 0x380

    or-int/2addr v1, v2

    and-int/lit16 v2, v0, 0x1c00

    or-int/2addr v1, v2

    const v2, 0xe000

    and-int/2addr v2, v0

    or-int/2addr v1, v2

    const/high16 v2, 0x70000

    and-int/2addr v0, v2

    or-int v21, v1, v0

    const/16 v22, 0x40

    move/from16 v17, p9

    move/from16 v18, v10

    move-object/from16 v20, v11

    move-object v11, v12

    move-object v12, v13

    move-wide v13, v14

    move-wide/from16 v15, p7

    invoke-static/range {v11 .. v22}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    goto :goto_12

    :cond_17
    move-object/from16 v20, v11

    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_12
    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v15

    if-eqz v15, :cond_18

    new-instance v0, Llyiahf/vczjk/uf0;

    move-object/from16 v1, p0

    move/from16 v4, p3

    move-object/from16 v5, p4

    move-wide/from16 v8, p7

    move/from16 v10, p9

    move/from16 v11, p10

    move-object/from16 v12, p11

    move-object/from16 v13, p12

    move/from16 v14, p14

    move v2, v6

    move v3, v7

    move-wide/from16 v6, p5

    invoke-direct/range {v0 .. v14}, Llyiahf/vczjk/uf0;-><init>(Llyiahf/vczjk/zl8;FFZLlyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V

    iput-object v0, v15, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_18
    return-void
.end method

.method public static OooO0o0()Llyiahf/vczjk/i62;
    .locals 2

    new-instance v0, Llyiahf/vczjk/i62;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/i62;-><init>(FF)V

    return-object v0
.end method

.method public static final OooO0oO(Landroid/content/Context;Llyiahf/vczjk/m85;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 14

    move-object/from16 v0, p6

    const/4 v1, 0x1

    instance-of v2, v0, Llyiahf/vczjk/ko7;

    if-eqz v2, :cond_0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/ko7;

    iget v3, v2, Llyiahf/vczjk/ko7;->label:I

    const/high16 v4, -0x80000000

    and-int v5, v3, v4

    if-eqz v5, :cond_0

    sub-int/2addr v3, v4

    iput v3, v2, Llyiahf/vczjk/ko7;->label:I

    goto :goto_0

    :cond_0
    new-instance v2, Llyiahf/vczjk/ko7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object v0, v2, Llyiahf/vczjk/ko7;->result:Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v4, v2, Llyiahf/vczjk/ko7;->label:I

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v6, 0x3

    const/4 v7, 0x2

    const/4 v8, 0x0

    if-eqz v4, :cond_4

    if-eq v4, v1, :cond_3

    if-eq v4, v7, :cond_2

    if-ne v4, v6, :cond_1

    iget-object p0, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/z75;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget-object p0, v2, Llyiahf/vczjk/ko7;->L$3:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/z75;

    iget-object v1, v2, Llyiahf/vczjk/ko7;->L$2:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    iget-object v4, v2, Llyiahf/vczjk/ko7;->L$1:Ljava/lang/Object;

    check-cast v4, Ljava/lang/String;

    iget-object v7, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    check-cast v7, Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_3

    :cond_3
    iget-object p0, v2, Llyiahf/vczjk/ko7;->L$3:Ljava/lang/Object;

    check-cast p0, Ljava/lang/String;

    iget-object v1, v2, Llyiahf/vczjk/ko7;->L$2:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    iget-object v4, v2, Llyiahf/vczjk/ko7;->L$1:Ljava/lang/Object;

    check-cast v4, Ljava/lang/String;

    iget-object v9, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    check-cast v9, Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v10, p0

    move-object p0, v9

    move-object v9, v1

    goto :goto_1

    :cond_4
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v4, p5

    invoke-static {p0, p1, v4}, Llyiahf/vczjk/vc6;->Oooo0OO(Landroid/content/Context;Llyiahf/vczjk/m85;Ljava/lang/String;)Llyiahf/vczjk/f95;

    move-result-object v0

    iput-object p0, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    move-object/from16 v4, p2

    iput-object v4, v2, Llyiahf/vczjk/ko7;->L$1:Ljava/lang/Object;

    move-object/from16 v9, p3

    iput-object v9, v2, Llyiahf/vczjk/ko7;->L$2:Ljava/lang/Object;

    move-object/from16 v10, p4

    iput-object v10, v2, Llyiahf/vczjk/ko7;->L$3:Ljava/lang/Object;

    iput v1, v2, Llyiahf/vczjk/ko7;->label:I

    new-instance v11, Llyiahf/vczjk/yp0;

    invoke-static {v2}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v12

    invoke-direct {v11, v1, v12}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v11}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance v12, Llyiahf/vczjk/ho7;

    const/4 v13, 0x0

    invoke-direct {v12, v11, v13}, Llyiahf/vczjk/ho7;-><init>(Llyiahf/vczjk/yp0;I)V

    invoke-virtual {v0, v12}, Llyiahf/vczjk/f95;->OooO0O0(Llyiahf/vczjk/a95;)V

    new-instance v12, Llyiahf/vczjk/ho7;

    invoke-direct {v12, v11, v1}, Llyiahf/vczjk/ho7;-><init>(Llyiahf/vczjk/yp0;I)V

    invoke-virtual {v0, v12}, Llyiahf/vczjk/f95;->OooO00o(Llyiahf/vczjk/a95;)V

    invoke-virtual {v11}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v3, :cond_5

    goto/16 :goto_5

    :cond_5
    :goto_1
    check-cast v0, Llyiahf/vczjk/z75;

    iput-object p0, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    iput-object v9, v2, Llyiahf/vczjk/ko7;->L$1:Ljava/lang/Object;

    iput-object v10, v2, Llyiahf/vczjk/ko7;->L$2:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/ko7;->L$3:Ljava/lang/Object;

    iput v7, v2, Llyiahf/vczjk/ko7;->label:I

    iget-object v1, v0, Llyiahf/vczjk/z75;->OooO0Oo:Ljava/util/HashMap;

    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_7

    :cond_6
    move-object v1, v5

    goto :goto_2

    :cond_7
    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v7, Llyiahf/vczjk/jo7;

    invoke-direct {v7, v0, p0, v4, v8}, Llyiahf/vczjk/jo7;-><init>(Llyiahf/vczjk/z75;Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v7, v2}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v3, :cond_6

    :goto_2
    if-ne v1, v3, :cond_8

    goto :goto_5

    :cond_8
    move-object v7, p0

    move-object p0, v0

    move-object v4, v9

    move-object v1, v10

    :goto_3
    iput-object p0, v2, Llyiahf/vczjk/ko7;->L$0:Ljava/lang/Object;

    iput-object v8, v2, Llyiahf/vczjk/ko7;->L$1:Ljava/lang/Object;

    iput-object v8, v2, Llyiahf/vczjk/ko7;->L$2:Ljava/lang/Object;

    iput-object v8, v2, Llyiahf/vczjk/ko7;->L$3:Ljava/lang/Object;

    iput v6, v2, Llyiahf/vczjk/ko7;->label:I

    iget-object v0, p0, Llyiahf/vczjk/z75;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_9

    goto :goto_4

    :cond_9
    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v6, Llyiahf/vczjk/io7;

    const/4 v8, 0x0

    move-object/from16 p2, p0

    move-object/from16 p5, v1

    move-object/from16 p4, v4

    move-object p1, v6

    move-object/from16 p3, v7

    move-object/from16 p6, v8

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/io7;-><init>(Llyiahf/vczjk/z75;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    move-object v1, p1

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v3, :cond_a

    move-object v5, v0

    :cond_a
    :goto_4
    if-ne v5, v3, :cond_b

    :goto_5
    return-object v3

    :cond_b
    return-object p0
.end method

.method public static final OooO0oo(FFFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 12

    sget-object v2, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance v3, Ljava/lang/Float;

    invoke-direct {v3, p0}, Ljava/lang/Float;-><init>(F)V

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    new-instance p0, Ljava/lang/Float;

    invoke-direct {p0, p2}, Ljava/lang/Float;-><init>(F)V

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    new-instance v5, Llyiahf/vczjk/zl;

    invoke-direct {v5, p0}, Llyiahf/vczjk/zl;-><init>(F)V

    new-instance v0, Llyiahf/vczjk/fg9;

    move-object v1, p3

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    new-instance v6, Llyiahf/vczjk/xl;

    const/16 p0, 0x38

    invoke-direct {v6, v2, v3, v5, p0}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;I)V

    new-instance v10, Llyiahf/vczjk/va9;

    move-object/from16 p0, p4

    invoke-direct {v10, p0}, Llyiahf/vczjk/va9;-><init>(Llyiahf/vczjk/ze3;)V

    const-wide/high16 v8, -0x8000000000000000L

    move-object/from16 v11, p5

    move-object v7, v0

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/vc6;->OooO(Llyiahf/vczjk/xl;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    move-object p0, p2

    :goto_0
    if-ne p0, p1, :cond_1

    return-object p0

    :cond_1
    return-object p2
.end method

.method public static synthetic OooOO0(FFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;
    .locals 6

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p2, 0x7

    const/4 p5, 0x0

    const/4 v0, 0x0

    invoke-static {v0, v0, p5, p2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p2

    :cond_0
    move-object v3, p2

    const/4 v2, 0x0

    move v0, p0

    move v1, p1

    move-object v4, p3

    move-object v5, p4

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vc6;->OooO0oo(FFFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/xl;Llyiahf/vczjk/t02;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    new-instance v3, Llyiahf/vczjk/s02;

    iget-object v2, p0, Llyiahf/vczjk/xl;->OooOOO0:Llyiahf/vczjk/m1a;

    invoke-direct {v3, p1, v2, v0, v1}, Llyiahf/vczjk/s02;-><init>(Llyiahf/vczjk/t02;Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    if-eqz p2, :cond_0

    iget-wide p1, p0, Llyiahf/vczjk/xl;->OooOOOo:J

    :goto_0
    move-object v2, p0

    move-wide v4, p1

    move-object v6, p3

    move-object v7, p4

    goto :goto_1

    :cond_0
    const-wide/high16 p1, -0x8000000000000000L

    goto :goto_0

    :goto_1
    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/vc6;->OooO(Llyiahf/vczjk/xl;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_1

    return-object p0

    :cond_1
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/xl;Ljava/lang/Float;Llyiahf/vczjk/wl;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    iget-object v6, p0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    new-instance v1, Llyiahf/vczjk/fg9;

    iget-object v3, p0, Llyiahf/vczjk/xl;->OooOOO0:Llyiahf/vczjk/m1a;

    move-object v5, p1

    move-object v2, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    move-object p1, v1

    if-eqz p3, :cond_0

    iget-wide p2, p0, Llyiahf/vczjk/xl;->OooOOOo:J

    goto :goto_0

    :cond_0
    const-wide/high16 p2, -0x8000000000000000L

    :goto_0
    invoke-static/range {p0 .. p5}, Llyiahf/vczjk/vc6;->OooO(Llyiahf/vczjk/xl;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_1

    return-object p0

    :cond_1
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final OooOOO(JLlyiahf/vczjk/nf6;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    const v1, 0x7fffffff

    if-ne p2, v0, :cond_1

    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p0

    if-eq p0, v1, :cond_0

    goto :goto_0

    :cond_0
    const-string p0, "Vertically scrollable component was measured with an infinity maximum height constraints, which is disallowed. One of the common reasons is nesting layouts like LazyColumn and Column(Modifier.verticalScroll()). If you want to add a header before the list of items please add a header as a separate item() before the main items() inside the LazyColumn scope. There could be other reasons for this to happen: your ComposeView was added into a LinearLayout with some weight, you applied Modifier.wrapContentSize(unbounded = true) or wrote a custom layout. Please try to remove the source of infinite constraints in the hierarchy above the scrolling container."

    invoke-static {p0}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    return-void

    :cond_1
    invoke-static {p0, p1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result p0

    if-eq p0, v1, :cond_2

    :goto_0
    return-void

    :cond_2
    const-string p0, "Horizontally scrollable component was measured with an infinity maximum width constraints, which is disallowed. One of the common reasons is nesting layouts like LazyRow and Row(Modifier.horizontalScroll()). If you want to add a header before the list of items please add a header as a separate item() before the main items() inside the LazyRow scope. There could be other reasons for this to happen: your ComposeView was added into a LinearLayout with some weight, you applied Modifier.wrapContentSize(unbounded = true) or wrote a custom layout. Please try to remove the source of infinite constraints in the hierarchy above the scrolling container."

    invoke-static {p0}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic OooOOO0(Llyiahf/vczjk/xl;Ljava/lang/Float;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;I)Ljava/lang/Object;
    .locals 1

    and-int/lit8 v0, p5, 0x4

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    :goto_0
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_1

    sget-object p3, Llyiahf/vczjk/o68;->Oooo00o:Llyiahf/vczjk/o68;

    :cond_1
    move-object p5, p4

    move-object p4, p3

    move p3, v0

    invoke-static/range {p0 .. p5}, Llyiahf/vczjk/vc6;->OooOO0o(Llyiahf/vczjk/xl;Ljava/lang/Float;Llyiahf/vczjk/wl;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOOO(II)I
    .locals 1

    invoke-static {p0}, Landroid/graphics/Color;->alpha(I)I

    move-result v0

    mul-int/2addr v0, p1

    div-int/lit16 v0, v0, 0xff

    invoke-static {p0, v0}, Llyiahf/vczjk/h31;->OooO0o0(II)I

    move-result p0

    return p0
.end method

.method public static final OooOOOo(Llyiahf/vczjk/wj7;FF)Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/wj7;->OooO00o:F

    iget v1, p0, Llyiahf/vczjk/wj7;->OooO0OO:F

    cmpg-float v1, p1, v1

    if-gtz v1, :cond_0

    cmpg-float p1, v0, p1

    if-gtz p1, :cond_0

    iget p1, p0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    cmpg-float p1, p2, p1

    if-gtz p1, :cond_0

    iget p0, p0, Llyiahf/vczjk/wj7;->OooO0O0:F

    cmpg-float p0, p0, p2

    if-gtz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooOOo(Llyiahf/vczjk/fl;JFLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V
    .locals 2

    const/4 v0, 0x0

    cmpg-float v0, p3, v0

    if-nez v0, :cond_0

    invoke-interface {p4}, Llyiahf/vczjk/yk;->OooO0O0()J

    move-result-wide v0

    goto :goto_0

    :cond_0
    iget-wide v0, p0, Llyiahf/vczjk/fl;->OooO0OO:J

    sub-long v0, p1, v0

    long-to-float v0, v0

    div-float/2addr v0, p3

    float-to-long v0, v0

    :goto_0
    iput-wide p1, p0, Llyiahf/vczjk/fl;->OooO0oO:J

    invoke-interface {p4, v0, v1}, Llyiahf/vczjk/yk;->OooO0o(J)Ljava/lang/Object;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    invoke-interface {p4, v0, v1}, Llyiahf/vczjk/yk;->OooO0Oo(J)Llyiahf/vczjk/dm;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fl;->OooO0o:Llyiahf/vczjk/dm;

    invoke-interface {p4, v0, v1}, Llyiahf/vczjk/yk;->OooO0o0(J)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-wide p1, p0, Llyiahf/vczjk/fl;->OooO0oO:J

    iput-wide p1, p0, Llyiahf/vczjk/fl;->OooO0oo:J

    iget-object p1, p0, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_1
    invoke-static {p0, p5}, Llyiahf/vczjk/vc6;->OoooO0O(Llyiahf/vczjk/fl;Llyiahf/vczjk/xl;)V

    invoke-interface {p6, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public static OooOOoo(Llyiahf/vczjk/gc;Landroid/util/LongSparseArray;)V
    .locals 6

    invoke-virtual {p1}, Landroid/util/LongSparseArray;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_2

    invoke-virtual {p1, v1}, Landroid/util/LongSparseArray;->keyAt(I)J

    move-result-wide v2

    invoke-virtual {p1, v2, v3}, Landroid/util/LongSparseArray;->get(J)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/x9;->OooOOo0(Ljava/lang/Object;)Landroid/view/translation/ViewTranslationResponse;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-static {v4}, Llyiahf/vczjk/x9;->OooOOO(Landroid/view/translation/ViewTranslationResponse;)Landroid/view/translation/TranslationResponseValue;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-static {v4}, Llyiahf/vczjk/x9;->OooOOo(Landroid/view/translation/TranslationResponseValue;)Ljava/lang/CharSequence;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object v5

    long-to-int v2, v2

    invoke-virtual {v5, v2}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/te8;

    if-eqz v2, :cond_1

    iget-object v2, v2, Llyiahf/vczjk/te8;->OooO00o:Llyiahf/vczjk/re8;

    if-eqz v2, :cond_1

    sget-object v3, Llyiahf/vczjk/ie8;->OooOO0O:Llyiahf/vczjk/ze8;

    iget-object v2, v2, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-object v2, v2, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_0

    const/4 v2, 0x0

    :cond_0
    check-cast v2, Llyiahf/vczjk/o0O00O;

    if-eqz v2, :cond_1

    iget-object v2, v2, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v2, Llyiahf/vczjk/oe3;

    if-eqz v2, :cond_1

    new-instance v3, Llyiahf/vczjk/an;

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v4}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;)V

    invoke-interface {v2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public static OooOo(Landroid/content/Context;ILjava/lang/String;)I
    .locals 0

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/e16;->Oooo00O(Landroid/content/Context;ILjava/lang/String;)Landroid/util/TypedValue;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/vc6;->Oooo0oO(Landroid/content/Context;Landroid/util/TypedValue;)I

    move-result p0

    return p0
.end method

.method public static OooOo0(IIII)J
    .locals 4

    const v0, 0x3fffe

    invoke-static {p0, v0}, Ljava/lang/Math;->min(II)I

    move-result p0

    const v1, 0x7fffffff

    if-ne p1, v1, :cond_0

    move p1, v1

    goto :goto_0

    :cond_0
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I

    move-result p1

    :goto_0
    if-ne p1, v1, :cond_1

    move v2, p0

    goto :goto_1

    :cond_1
    move v2, p1

    :goto_1
    const/16 v3, 0x1fff

    if-ge v2, v3, :cond_2

    goto :goto_2

    :cond_2
    const/16 v0, 0x7fff

    if-ge v2, v0, :cond_3

    const v0, 0xfffe

    goto :goto_2

    :cond_3
    const v0, 0xffff

    if-ge v2, v0, :cond_4

    const/16 v0, 0x7ffe

    goto :goto_2

    :cond_4
    const v0, 0x3ffff

    if-ge v2, v0, :cond_6

    const/16 v0, 0x1ffe

    :goto_2
    if-ne p3, v1, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {v0, p3}, Ljava/lang/Math;->min(II)I

    move-result v1

    :goto_3
    invoke-static {v0, p2}, Ljava/lang/Math;->min(II)I

    move-result p2

    invoke-static {p0, p1, p2, v1}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p0

    return-wide p0

    :cond_6
    invoke-static {v2}, Llyiahf/vczjk/uk1;->OooOO0o(I)Ljava/lang/Void;

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0
.end method

.method public static OooOo00(IIII)J
    .locals 4

    const v0, 0x3fffe

    invoke-static {p2, v0}, Ljava/lang/Math;->min(II)I

    move-result p2

    const v1, 0x7fffffff

    if-ne p3, v1, :cond_0

    move p3, v1

    goto :goto_0

    :cond_0
    invoke-static {p3, v0}, Ljava/lang/Math;->min(II)I

    move-result p3

    :goto_0
    if-ne p3, v1, :cond_1

    move v2, p2

    goto :goto_1

    :cond_1
    move v2, p3

    :goto_1
    const/16 v3, 0x1fff

    if-ge v2, v3, :cond_2

    goto :goto_2

    :cond_2
    const/16 v0, 0x7fff

    if-ge v2, v0, :cond_3

    const v0, 0xfffe

    goto :goto_2

    :cond_3
    const v0, 0xffff

    if-ge v2, v0, :cond_4

    const/16 v0, 0x7ffe

    goto :goto_2

    :cond_4
    const v0, 0x3ffff

    if-ge v2, v0, :cond_6

    const/16 v0, 0x1ffe

    :goto_2
    if-ne p1, v1, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {v0, p1}, Ljava/lang/Math;->min(II)I

    move-result v1

    :goto_3
    invoke-static {v0, p0}, Ljava/lang/Math;->min(II)I

    move-result p0

    invoke-static {p0, v1, p2, p3}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p0

    return-wide p0

    :cond_6
    invoke-static {v2}, Llyiahf/vczjk/uk1;->OooOO0o(I)Ljava/lang/Void;

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/i43;

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/i43;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/yo1;I)V

    const/4 p1, 0x1

    invoke-static {v0, p1, v0, p0}, Llyiahf/vczjk/vl6;->OooOooO(Llyiahf/vczjk/x88;ZLlyiahf/vczjk/x88;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p0
.end method

.method public static OooOo0o(Landroid/content/Context;II)I
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/vc6;->OooOoO0(Landroid/content/Context;I)Ljava/lang/Integer;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result p0

    return p0

    :cond_0
    return p2
.end method

.method public static OooOoO(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;
    .locals 1

    invoke-static {}, Llyiahf/vczjk/yr7;->OooO0O0()Llyiahf/vczjk/yr7;

    move-result-object v0

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/yr7;->OooO0OO(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    move-result-object p0

    return-object p0
.end method

.method public static OooOoO0(Landroid/content/Context;I)Ljava/lang/Integer;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/e16;->OooOooo(Landroid/content/Context;I)Landroid/util/TypedValue;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/vc6;->Oooo0oO(Landroid/content/Context;Landroid/util/TypedValue;)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOoOO(Llyiahf/vczjk/or1;)F
    .locals 1

    sget-object v0, Llyiahf/vczjk/vp3;->OooOOo:Llyiahf/vczjk/vp3;

    invoke-interface {p0, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/fo5;

    if-eqz p0, :cond_0

    invoke-interface {p0}, Llyiahf/vczjk/fo5;->Oooo0oO()F

    move-result p0

    goto :goto_0

    :cond_0
    const/high16 p0, 0x3f800000    # 1.0f

    :goto_0
    const/4 v0, 0x0

    cmpl-float v0, p0, v0

    if-ltz v0, :cond_1

    return p0

    :cond_1
    const-string v0, "negative scale factor"

    invoke-static {v0}, Llyiahf/vczjk/w07;->OooO0O0(Ljava/lang/String;)V

    return p0
.end method

.method public static OooOoo(Landroid/content/Context;Ljava/util/Date;)Ljava/lang/String;
    .locals 4

    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    const-wide/16 v2, 0x3e8

    div-long/2addr v0, v2

    long-to-int p1, v0

    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/Calendar;->getTimeInMillis()J

    move-result-wide v0

    div-long/2addr v0, v2

    long-to-int v0, v0

    sub-int/2addr v0, p1

    if-gez v0, :cond_0

    const-string p0, ""

    return-object p0

    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    const/16 p1, 0xf

    if-ge v0, p1, :cond_1

    sget p1, Lsi/virag/fuzzydateformatter/R$string;->fuzzydatetime__now:I

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_1
    const/16 p1, 0x3c

    if-ge v0, p1, :cond_2

    sget p1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__seconds_ago:I

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_2
    const/16 v1, 0xe10

    if-ge v0, v1, :cond_3

    sget v1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__minutes_ago:I

    div-int/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, v1, v0, p1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_3
    const p1, 0x15180

    if-ge v0, p1, :cond_4

    sget p1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__hours_ago:I

    div-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_4
    const v1, 0x93a80

    if-ge v0, v1, :cond_5

    sget v1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__days_ago:I

    div-int/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, v1, v0, p1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_5
    const p1, 0x24ea00

    if-ge v0, p1, :cond_6

    sget p1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__weeks_ago:I

    div-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_6
    const v1, 0x1baf800

    if-ge v0, v1, :cond_7

    sget v1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__months_ago:I

    div-int/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, v1, v0, p1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_7
    sget p1, Lsi/virag/fuzzydateformatter/R$plurals;->fuzzydatetime__years_ago:I

    div-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/res/Resources;->getQuantityString(II[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/up3;->OooOOo:Llyiahf/vczjk/up3;

    invoke-interface {p0, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/xn5;

    if-eqz p0, :cond_0

    return-object p0

    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "A MonotonicFrameClock is not available in this CoroutineContext. Callers should supply an appropriate MonotonicFrameClock using withContext."

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOooO(I)Z
    .locals 21

    if-eqz p0, :cond_5

    sget-object v1, Llyiahf/vczjk/h31;->OooO00o:Ljava/lang/ThreadLocal;

    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, [D

    const/4 v3, 0x3

    if-nez v2, :cond_0

    new-array v2, v3, [D

    invoke-virtual {v1, v2}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    :cond_0
    invoke-static/range {p0 .. p0}, Landroid/graphics/Color;->red(I)I

    move-result v1

    invoke-static/range {p0 .. p0}, Landroid/graphics/Color;->green(I)I

    move-result v4

    invoke-static/range {p0 .. p0}, Landroid/graphics/Color;->blue(I)I

    move-result v5

    array-length v6, v2

    if-ne v6, v3, :cond_4

    int-to-double v6, v1

    const-wide v8, 0x406fe00000000000L    # 255.0

    div-double/2addr v6, v8

    const-wide v10, 0x3fa4b5dcc63f1412L    # 0.04045

    cmpg-double v1, v6, v10

    const-wide v12, 0x4003333333333333L    # 2.4

    const-wide v14, 0x3ff0e147ae147ae1L    # 1.055

    const-wide v16, 0x3fac28f5c28f5c29L    # 0.055

    const-wide v18, 0x4029d70a3d70a3d7L    # 12.92

    if-gez v1, :cond_1

    div-double v6, v6, v18

    goto :goto_0

    :cond_1
    add-double v6, v6, v16

    div-double/2addr v6, v14

    invoke-static {v6, v7, v12, v13}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v6

    :goto_0
    int-to-double v3, v4

    div-double/2addr v3, v8

    cmpg-double v1, v3, v10

    if-gez v1, :cond_2

    div-double v3, v3, v18

    :goto_1
    const/16 v20, 0x0

    goto :goto_2

    :cond_2
    add-double v3, v3, v16

    div-double/2addr v3, v14

    invoke-static {v3, v4, v12, v13}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v3

    goto :goto_1

    :goto_2
    int-to-double v0, v5

    div-double/2addr v0, v8

    cmpg-double v5, v0, v10

    if-gez v5, :cond_3

    div-double v0, v0, v18

    goto :goto_3

    :cond_3
    add-double v0, v0, v16

    div-double/2addr v0, v14

    invoke-static {v0, v1, v12, v13}, Ljava/lang/Math;->pow(DD)D

    move-result-wide v0

    :goto_3
    const-wide v8, 0x3fda64c2f837b4a2L    # 0.4124

    mul-double/2addr v8, v6

    const-wide v10, 0x3fd6e2eb1c432ca5L    # 0.3576

    mul-double/2addr v10, v3

    add-double/2addr v10, v8

    const-wide v8, 0x3fc71a9fbe76c8b4L    # 0.1805

    mul-double/2addr v8, v0

    add-double/2addr v8, v10

    const-wide/high16 v10, 0x4059000000000000L    # 100.0

    mul-double/2addr v8, v10

    aput-wide v8, v2, v20

    const-wide v8, 0x3fcb367a0f9096bcL    # 0.2126

    mul-double/2addr v8, v6

    const-wide v12, 0x3fe6e2eb1c432ca5L    # 0.7152

    mul-double/2addr v12, v3

    add-double/2addr v12, v8

    const-wide v8, 0x3fb27bb2fec56d5dL    # 0.0722

    mul-double/2addr v8, v0

    add-double/2addr v8, v12

    mul-double/2addr v8, v10

    const/4 v5, 0x1

    aput-wide v8, v2, v5

    const-wide v12, 0x3f93c36113404ea5L    # 0.0193

    mul-double/2addr v6, v12

    const-wide v12, 0x3fbe83e425aee632L    # 0.1192

    mul-double/2addr v3, v12

    add-double/2addr v3, v6

    const-wide v6, 0x3fee6a7ef9db22d1L    # 0.9505

    mul-double/2addr v0, v6

    add-double/2addr v0, v3

    mul-double/2addr v0, v10

    const/4 v3, 0x2

    aput-wide v0, v2, v3

    div-double/2addr v8, v10

    const-wide/high16 v0, 0x3fe0000000000000L    # 0.5

    cmpl-double v0, v8, v0

    if-lez v0, :cond_6

    return v5

    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "outXyz must have a length of 3."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_5
    const/16 v20, 0x0

    :cond_6
    return v20
.end method

.method public static OooOooo(I)Z
    .locals 1

    const v0, 0x8000

    and-int/2addr p0, v0

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static Oooo(Ljava/lang/Throwable;)V
    .locals 1

    instance-of v0, p0, Ljava/lang/VirtualMachineError;

    if-nez v0, :cond_2

    instance-of v0, p0, Ljava/lang/ThreadDeath;

    if-nez v0, :cond_1

    instance-of v0, p0, Ljava/lang/LinkageError;

    if-nez v0, :cond_0

    return-void

    :cond_0
    check-cast p0, Ljava/lang/LinkageError;

    throw p0

    :cond_1
    check-cast p0, Ljava/lang/ThreadDeath;

    throw p0

    :cond_2
    check-cast p0, Ljava/lang/VirtualMachineError;

    throw p0
.end method

.method public static final Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/era;
    .locals 1

    new-instance v0, Llyiahf/vczjk/o15;

    invoke-direct {v0, p1}, Llyiahf/vczjk/o15;-><init>(Llyiahf/vczjk/ze3;)V

    const/4 p1, 0x1

    invoke-static {p1, p0}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance p1, Llyiahf/vczjk/era;

    invoke-direct {p1, v0, p0}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object p1
.end method

.method public static Oooo000(I)Z
    .locals 3

    const v0, -0x10001

    and-int/2addr p0, v0

    const/16 v0, 0xf

    const/4 v1, 0x1

    if-eq p0, v0, :cond_6

    const/16 v0, 0xff

    if-eq p0, v0, :cond_6

    const v0, 0x8000

    const/4 v2, 0x0

    if-eq p0, v0, :cond_4

    const v0, 0x800f

    if-eq p0, v0, :cond_1

    const v0, 0x80ff

    if-eq p0, v0, :cond_6

    if-nez p0, :cond_0

    return v1

    :cond_0
    return v2

    :cond_1
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1c

    if-lt p0, v0, :cond_3

    const/16 v0, 0x1d

    if-le p0, v0, :cond_2

    goto :goto_0

    :cond_2
    return v2

    :cond_3
    :goto_0
    return v1

    :cond_4
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1e

    if-lt p0, v0, :cond_5

    return v1

    :cond_5
    return v2

    :cond_6
    return v1
.end method

.method public static Oooo00O(IFI)I
    .locals 1

    invoke-static {p2}, Landroid/graphics/Color;->alpha(I)I

    move-result v0

    int-to-float v0, v0

    mul-float/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    move-result p1

    invoke-static {p2, p1}, Llyiahf/vczjk/h31;->OooO0o0(II)I

    move-result p1

    invoke-static {p1, p0}, Llyiahf/vczjk/h31;->OooO0OO(II)I

    move-result p0

    return p0
.end method

.method public static Oooo00o(III)I
    .locals 2

    and-int/lit8 p1, p1, 0x8

    if-eqz p1, :cond_0

    add-int/lit8 p0, p0, -0x1

    :cond_0
    if-gt p2, p0, :cond_1

    sub-int/2addr p0, p2

    return p0

    :cond_1
    new-instance p1, Ljava/io/IOException;

    const-string v0, "PROTOCOL_ERROR padding "

    const-string v1, " > remaining length "

    invoke-static {p2, p0, v0, v1}, Llyiahf/vczjk/u81;->OooO0oo(IILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public static final Oooo0OO(Landroid/content/Context;Llyiahf/vczjk/m85;Ljava/lang/String;)Llyiahf/vczjk/f95;
    .locals 3

    const/4 v0, 0x1

    instance-of v1, p1, Llyiahf/vczjk/l85;

    if-eqz v1, :cond_1

    const-string v1, "__LottieInternalDefaultCacheKey__"

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast p1, Llyiahf/vczjk/l85;

    iget-object p1, p1, Llyiahf/vczjk/l85;->OooO00o:Ljava/lang/String;

    sget-object p2, Llyiahf/vczjk/e85;->OooO00o:Ljava/util/HashMap;

    const-string p2, "asset_"

    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/b85;

    invoke-direct {v1, p0, v0, p1, p2}, Llyiahf/vczjk/b85;-><init>(Landroid/content/Context;ILjava/lang/String;Ljava/lang/String;)V

    invoke-static {p2, v1, v2}, Llyiahf/vczjk/e85;->OooO00o(Ljava/lang/String;Ljava/util/concurrent/Callable;Ljava/lang/Runnable;)Llyiahf/vczjk/f95;

    move-result-object p0

    return-object p0

    :cond_0
    check-cast p1, Llyiahf/vczjk/l85;

    iget-object p1, p1, Llyiahf/vczjk/l85;->OooO00o:Ljava/lang/String;

    sget-object v1, Llyiahf/vczjk/e85;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/b85;

    invoke-direct {v1, p0, v0, p1, p2}, Llyiahf/vczjk/b85;-><init>(Landroid/content/Context;ILjava/lang/String;Ljava/lang/String;)V

    invoke-static {p2, v1, v2}, Llyiahf/vczjk/e85;->OooO00o(Ljava/lang/String;Ljava/util/concurrent/Callable;Ljava/lang/Runnable;)Llyiahf/vczjk/f95;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0
.end method

.method public static final Oooo0o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lg0;
    .locals 7

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    sget-object v3, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v0, :cond_0

    new-instance v2, Llyiahf/vczjk/ow;

    const/16 v4, 0xe

    invoke-direct {v2, v4}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast v2, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    const/16 v6, 0x31

    const/4 v1, 0x0

    move-object v4, p0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/wl8;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/am8;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/zl8;

    move-result-object p0

    move-object v1, v4

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v0, :cond_1

    new-instance v2, Llyiahf/vczjk/cu8;

    invoke-direct {v2}, Llyiahf/vczjk/cu8;-><init>()V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v2, Llyiahf/vczjk/cu8;

    move-object v1, v4

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v1, v3

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_2

    if-ne v4, v0, :cond_3

    :cond_2
    new-instance v4, Llyiahf/vczjk/lg0;

    invoke-direct {v4, p0, v2}, Llyiahf/vczjk/lg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/cu8;)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v4, Llyiahf/vczjk/lg0;

    return-object v4
.end method

.method public static final Oooo0o0(Llyiahf/vczjk/pq4;Llyiahf/vczjk/nf6;)I
    .locals 2

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne p1, v0, :cond_0

    iget-wide p0, p0, Llyiahf/vczjk/pq4;->OooOo0O:J

    const-wide v0, 0xffffffffL

    and-long/2addr p0, v0

    :goto_0
    long-to-int p0, p0

    return p0

    :cond_0
    iget-wide p0, p0, Llyiahf/vczjk/pq4;->OooOo0O:J

    const/16 v0, 0x20

    shr-long/2addr p0, v0

    goto :goto_0
.end method

.method public static Oooo0oO(Landroid/content/Context;Landroid/util/TypedValue;)I
    .locals 1

    iget v0, p1, Landroid/util/TypedValue;->resourceId:I

    if-eqz v0, :cond_0

    invoke-virtual {p0, v0}, Landroid/content/Context;->getColor(I)I

    move-result p0

    return p0

    :cond_0
    iget p0, p1, Landroid/util/TypedValue;->data:I

    return p0
.end method

.method public static final Oooo0oo(DD)D
    .locals 2

    invoke-static {p0, p1}, Ljava/lang/Math;->abs(D)D

    move-result-wide v0

    invoke-static {v0, v1, p2, p3}, Ljava/lang/Math;->pow(DD)D

    move-result-wide p2

    invoke-static {p2, p3, p0, p1}, Ljava/lang/Math;->copySign(DD)D

    move-result-wide p0

    return-wide p0
.end method

.method public static OoooO0(I)Ljava/lang/String;
    .locals 1

    const/4 v0, -0x1

    if-ne p0, v0, :cond_0

    const-string p0, "Unspecified"

    return-object p0

    :cond_0
    if-nez p0, :cond_1

    const-string p0, "None"

    return-object p0

    :cond_1
    const/4 v0, 0x1

    if-ne p0, v0, :cond_2

    const-string p0, "Characters"

    return-object p0

    :cond_2
    const/4 v0, 0x2

    if-ne p0, v0, :cond_3

    const-string p0, "Words"

    return-object p0

    :cond_3
    const/4 v0, 0x3

    if-ne p0, v0, :cond_4

    const-string p0, "Sentences"

    return-object p0

    :cond_4
    const-string p0, "Invalid"

    return-object p0
.end method

.method public static OoooO00(Landroid/graphics/drawable/Drawable;)Landroid/graphics/Bitmap;
    .locals 8

    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    move-result v0

    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    move-result v1

    instance-of v2, p0, Landroid/graphics/drawable/BitmapDrawable;

    if-eqz v2, :cond_2

    check-cast p0, Landroid/graphics/drawable/BitmapDrawable;

    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v2

    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v2

    if-ne v0, v2, :cond_0

    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v2

    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v2

    if-ne v1, v2, :cond_0

    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object p0

    return-object p0

    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object p0

    const/4 v2, 0x1

    invoke-static {p0, v0, v1, v2}, Landroid/graphics/Bitmap;->createScaledBitmap(Landroid/graphics/Bitmap;IIZ)Landroid/graphics/Bitmap;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "bitmap is null"

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    move-result-object v2

    iget v3, v2, Landroid/graphics/Rect;->left:I

    iget v4, v2, Landroid/graphics/Rect;->top:I

    iget v5, v2, Landroid/graphics/Rect;->right:I

    iget v2, v2, Landroid/graphics/Rect;->bottom:I

    sget-object v6, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    invoke-static {v0, v1, v6}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    move-result-object v6

    const/4 v7, 0x0

    invoke-virtual {p0, v7, v7, v0, v1}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    new-instance v0, Landroid/graphics/Canvas;

    invoke-direct {v0, v6}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    invoke-virtual {p0, v0}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    invoke-virtual {p0, v3, v4, v5, v2}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    return-object v6
.end method

.method public static final OoooO0O(Llyiahf/vczjk/fl;Llyiahf/vczjk/xl;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p1, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/fl;->OooO0o:Llyiahf/vczjk/dm;

    invoke-virtual {v0}, Llyiahf/vczjk/dm;->OooO0O0()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v4

    invoke-virtual {v0, v4, v3}, Llyiahf/vczjk/dm;->OooO0o0(FI)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget-wide v0, p0, Llyiahf/vczjk/fl;->OooO0oo:J

    iput-wide v0, p1, Llyiahf/vczjk/xl;->OooOOo0:J

    iget-wide v0, p0, Llyiahf/vczjk/fl;->OooO0oO:J

    iput-wide v0, p1, Llyiahf/vczjk/xl;->OooOOOo:J

    iget-object p0, p0, Llyiahf/vczjk/fl;->OooO:Llyiahf/vczjk/qs5;

    check-cast p0, Llyiahf/vczjk/fw8;

    invoke-virtual {p0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    iput-boolean p0, p1, Llyiahf/vczjk/xl;->OooOOo:Z

    return-void
.end method


# virtual methods
.method public OooOOo0(Ljava/util/Map;)Llyiahf/vczjk/uw7;
    .locals 4

    new-instance v0, Llyiahf/vczjk/uw7;

    invoke-direct {v0}, Llyiahf/vczjk/uw7;-><init>()V

    const-string v1, "name"

    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const-string v1, "rule"

    :goto_0
    iput-object v1, v0, Llyiahf/vczjk/uw7;->OooO00o:Ljava/lang/String;

    const-string v1, "description"

    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-eqz v2, :cond_1

    move-object v1, v2

    :cond_1
    iput-object v1, v0, Llyiahf/vczjk/uw7;->OooO0O0:Ljava/lang/String;

    const-string v1, "priority"

    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    goto :goto_1

    :cond_2
    const v1, 0x7ffffffe

    :goto_1
    iput v1, v0, Llyiahf/vczjk/uw7;->OooO0OO:I

    const-string v1, "compositeRuleType"

    invoke-interface {p1, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    const-string v2, "condition"

    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v2, :cond_4

    if-eqz v1, :cond_3

    goto :goto_2

    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "The rule condition must be specified"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    :goto_2
    iput-object v2, v0, Llyiahf/vczjk/uw7;->OooO0Oo:Ljava/lang/String;

    const-string v2, "actions"

    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    if-eqz v2, :cond_5

    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_6

    :cond_5
    if-eqz v1, :cond_e

    :cond_6
    iput-object v2, v0, Llyiahf/vczjk/uw7;->OooO0o0:Ljava/util/List;

    const-string v2, "composingRules"

    invoke-interface {p1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    if-eqz p1, :cond_8

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_8

    if-eqz v1, :cond_7

    goto :goto_3

    :cond_7
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Non-composite rules cannot have composing rules"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    :goto_3
    if-eqz p1, :cond_9

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_a

    :cond_9
    if-nez v1, :cond_d

    :cond_a
    if-eqz p1, :cond_c

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_b

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map;

    invoke-virtual {p0, v3}, Llyiahf/vczjk/vc6;->OooOOo0(Ljava/util/Map;)Llyiahf/vczjk/uw7;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_b
    iput-object v2, v0, Llyiahf/vczjk/uw7;->OooO0o:Ljava/util/ArrayList;

    iput-object v1, v0, Llyiahf/vczjk/uw7;->OooO0oO:Ljava/lang/String;

    :cond_c
    return-object v0

    :cond_d
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Composite rules must have composing rules specified"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_e
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "The rule action(s) must be specified"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public abstract Oooo0O0(Ljava/io/StringReader;)Ljava/util/ArrayList;
.end method
