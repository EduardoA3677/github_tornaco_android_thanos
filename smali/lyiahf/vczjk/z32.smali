.class public final Llyiahf/vczjk/z32;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/z32;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/z32;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/z32;->OooO00o:Llyiahf/vczjk/z32;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zp8;Llyiahf/vczjk/rf1;I)V
    .locals 30

    move-object/from16 v0, p1

    move/from16 v1, p3

    const/16 v2, 0xe

    const/4 v3, 0x1

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    const v5, 0x7f677649

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    const/4 v6, 0x2

    const/4 v7, 0x4

    if-eqz v5, :cond_0

    move v5, v7

    goto :goto_0

    :cond_0
    move v5, v6

    :goto_0
    or-int/2addr v5, v1

    and-int/lit8 v8, v5, 0x3

    const/4 v9, 0x0

    if-eq v8, v6, :cond_1

    move v6, v3

    goto :goto_1

    :cond_1
    move v6, v9

    :goto_1
    and-int/lit8 v8, v5, 0x1

    invoke-virtual {v4, v8, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v6

    if-eqz v6, :cond_10

    iget v6, v0, Llyiahf/vczjk/zp8;->OooO0oO:F

    invoke-static {v6}, Ljava/lang/Float;->isNaN(F)Z

    move-result v8

    if-nez v8, :cond_f

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    const v8, 0x7fffffff

    and-int/2addr v6, v8

    const/high16 v8, 0x7f800000    # Float.POSITIVE_INFINITY

    if-ge v6, v8, :cond_f

    iget-object v6, v0, Llyiahf/vczjk/zp8;->OooO:Llyiahf/vczjk/fx9;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    const/4 v10, 0x0

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v8, v10

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v8, :cond_2

    if-ne v10, v11, :cond_3

    :cond_2
    new-instance v8, Llyiahf/vczjk/o0oOOo;

    const/4 v10, 0x6

    invoke-direct {v8, v0, v10}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-static {v8}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object v10

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v10, Llyiahf/vczjk/p29;

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/n21;

    iget-wide v12, v8, Llyiahf/vczjk/n21;->OooO00o:J

    sget-object v8, Llyiahf/vczjk/zo5;->OooOOOO:Llyiahf/vczjk/zo5;

    invoke-static {v8, v4}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v8

    invoke-static {v12, v13, v8, v4}, Llyiahf/vczjk/pq8;->OooO00o(JLlyiahf/vczjk/wl;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p29;

    move-result-object v8

    new-instance v10, Llyiahf/vczjk/f5;

    const/16 v12, 0xb

    invoke-direct {v10, v0, v12}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v12, -0x62e0c0ee

    invoke-static {v12, v10, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v23

    const v10, 0x292236d1

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v10, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v12, v0, Llyiahf/vczjk/zp8;->OooO00o:Llyiahf/vczjk/hl5;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v12, :cond_4

    if-ne v13, v11, :cond_5

    :cond_4
    new-instance v13, Llyiahf/vczjk/fl0;

    invoke-direct {v13, v8, v3}, Llyiahf/vczjk/fl0;-><init>(Llyiahf/vczjk/p29;I)V

    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-static {v10, v13}, Landroidx/compose/ui/draw/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-ne v12, v11, :cond_6

    new-instance v12, Llyiahf/vczjk/ow;

    const/16 v13, 0x16

    invoke-direct {v12, v13}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v4, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v12, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, v12}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v12, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v11, :cond_7

    sget-object v13, Llyiahf/vczjk/y32;->OooOOO:Llyiahf/vczjk/y32;

    invoke-virtual {v4, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v13, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    invoke-static {v8, v12, v13}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v12, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v12, v9}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v12

    iget v13, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v4, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_8

    invoke-virtual {v4, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v12, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_9

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v12, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_a

    :cond_9
    invoke-static {v13, v4, v13, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v8, v0, Llyiahf/vczjk/zp8;->OooO0oo:Llyiahf/vczjk/zy4;

    invoke-static {v10, v8}, Llyiahf/vczjk/uoa;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kna;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/up;->OooO00o:Llyiahf/vczjk/jh1;

    and-int/2addr v5, v2

    if-ne v5, v7, :cond_b

    move v9, v3

    goto :goto_3

    :cond_b
    const/4 v9, 0x0

    :goto_3
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v9, :cond_c

    if-ne v5, v11, :cond_d

    :cond_c
    new-instance v5, Llyiahf/vczjk/x32;

    invoke-direct {v5, v0}, Llyiahf/vczjk/x32;-><init>(Llyiahf/vczjk/zp8;)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v5, Llyiahf/vczjk/z23;

    iget-wide v9, v6, Llyiahf/vczjk/fx9;->OooO0OO:J

    sget-object v19, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v11, :cond_e

    new-instance v7, Llyiahf/vczjk/oOOO0OO0;

    const/16 v11, 0xf

    invoke-direct {v7, v11}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    move-object/from16 v18, v7

    check-cast v18, Llyiahf/vczjk/le3;

    iget-object v14, v0, Llyiahf/vczjk/zp8;->OooO0O0:Llyiahf/vczjk/a91;

    const/16 v26, 0x0

    const v27, 0x186c36

    move-object/from16 v25, v4

    move-object v4, v8

    move-wide v10, v9

    iget-wide v8, v6, Llyiahf/vczjk/fx9;->OooO0Oo:J

    move-wide v12, v10

    iget-wide v10, v6, Llyiahf/vczjk/fx9;->OooO0o:J

    iget-wide v6, v6, Llyiahf/vczjk/fx9;->OooO0o0:J

    iget-object v15, v0, Llyiahf/vczjk/zp8;->OooO0OO:Llyiahf/vczjk/rn9;

    const/16 v16, 0x0

    iget-object v2, v0, Llyiahf/vczjk/zp8;->OooO0Oo:Llyiahf/vczjk/rn9;

    const/16 v20, 0x0

    const/16 v21, 0x0

    iget-object v3, v0, Llyiahf/vczjk/zp8;->OooO0o0:Llyiahf/vczjk/a91;

    move-object/from16 v17, v2

    iget v2, v0, Llyiahf/vczjk/zp8;->OooO0oO:F

    move-wide/from16 v28, v12

    move-wide v12, v6

    move-wide/from16 v6, v28

    move/from16 v24, v2

    move-object/from16 v22, v3

    invoke-static/range {v4 .. v27}, Llyiahf/vczjk/up;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z23;JJJJLlyiahf/vczjk/a91;Llyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/le3;Llyiahf/vczjk/px;IZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/rf1;II)V

    move-object/from16 v2, v25

    const/4 v3, 0x1

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The expandedHeight is expected to be specified and finite"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_10
    move-object v2, v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_11

    new-instance v3, Llyiahf/vczjk/e2;

    const/16 v5, 0xe

    move-object/from16 v4, p0

    invoke-direct {v3, v4, v0, v1, v5}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    return-void

    :cond_11
    move-object/from16 v4, p0

    return-void
.end method
