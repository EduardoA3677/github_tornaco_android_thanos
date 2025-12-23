.class public abstract Llyiahf/vczjk/yu3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x1

    and-int/2addr v0, v0

    if-nez v0, :cond_0

    const-string v0, "width and height must be >= 0"

    invoke-static {v0}, Llyiahf/vczjk/rz3;->OooO00o(Ljava/lang/String;)V

    :cond_0
    const/4 v0, 0x0

    invoke-static {v0, v0, v0, v0}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    return-void
.end method

.method public static final OooO00o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Llyiahf/vczjk/k43;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v1, p0

    move-object/from16 v7, p1

    move-object/from16 v8, p2

    move-object/from16 v2, p3

    move/from16 v9, p7

    const-string v0, "executeImageRequest"

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "imageOptions"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v14, p6

    check-cast v14, Llyiahf/vczjk/zf1;

    const v0, -0x2cd0dff3    # -7.52157E11f

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v9, 0x6

    const/4 v3, 0x4

    if-nez v0, :cond_2

    and-int/lit8 v0, v9, 0x8

    if-nez v0, :cond_0

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    goto :goto_0

    :cond_0
    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    :goto_0
    if-eqz v0, :cond_1

    move v0, v3

    goto :goto_1

    :cond_1
    const/4 v0, 0x2

    :goto_1
    or-int/2addr v0, v9

    goto :goto_2

    :cond_2
    move v0, v9

    :goto_2
    and-int/lit8 v4, v9, 0x30

    if-nez v4, :cond_4

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x20

    goto :goto_3

    :cond_3
    const/16 v4, 0x10

    :goto_3
    or-int/2addr v0, v4

    :cond_4
    and-int/lit16 v4, v9, 0x180

    if-nez v4, :cond_6

    invoke-virtual {v14, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_5

    const/16 v4, 0x100

    goto :goto_4

    :cond_5
    const/16 v4, 0x80

    :goto_4
    or-int/2addr v0, v4

    :cond_6
    and-int/lit16 v4, v9, 0xc00

    const/16 v5, 0x800

    if-nez v4, :cond_8

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_7

    move v4, v5

    goto :goto_5

    :cond_7
    const/16 v4, 0x400

    :goto_5
    or-int/2addr v0, v4

    :cond_8
    and-int/lit16 v4, v9, 0x6000

    if-nez v4, :cond_a

    move-object/from16 v4, p4

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_9

    const/16 v6, 0x4000

    goto :goto_6

    :cond_9
    const/16 v6, 0x2000

    :goto_6
    or-int/2addr v0, v6

    goto :goto_7

    :cond_a
    move-object/from16 v4, p4

    :goto_7
    const/high16 v6, 0x30000

    and-int/2addr v6, v9

    if-nez v6, :cond_c

    move-object/from16 v6, p5

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_b

    const/high16 v10, 0x20000

    goto :goto_8

    :cond_b
    const/high16 v10, 0x10000

    :goto_8
    or-int/2addr v0, v10

    goto :goto_9

    :cond_c
    move-object/from16 v6, p5

    :goto_9
    const v10, 0x12493

    and-int/2addr v10, v0

    const v11, 0x12492

    if-ne v10, v11, :cond_e

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v10

    if-nez v10, :cond_d

    goto :goto_a

    :cond_d
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_10

    :cond_e
    :goto_a
    const v10, 0x3ca5bbac

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v10, v0, 0xe

    const/4 v11, 0x0

    const/4 v12, 0x1

    if-eq v10, v3, :cond_10

    and-int/lit8 v3, v0, 0x8

    if-eqz v3, :cond_f

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_f

    goto :goto_b

    :cond_f
    move v3, v11

    goto :goto_c

    :cond_10
    :goto_b
    move v3, v12

    :goto_c
    and-int/lit16 v10, v0, 0x1c00

    if-ne v10, v5, :cond_11

    goto :goto_d

    :cond_11
    move v12, v11

    :goto_d
    or-int/2addr v3, v12

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v3, :cond_12

    if-ne v5, v10, :cond_13

    :cond_12
    sget-object v3, Llyiahf/vczjk/bv3;->OooO00o:Llyiahf/vczjk/bv3;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v5, Llyiahf/vczjk/qs5;

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, 0x3ca5cf7d

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v3, v12

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v3, :cond_14

    if-ne v12, v10, :cond_15

    :cond_14
    new-instance v12, Llyiahf/vczjk/uu3;

    const/4 v3, 0x0

    invoke-direct {v12, v7, v5, v3}, Llyiahf/vczjk/uu3;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v12, Llyiahf/vczjk/ze3;

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v2, v12, v14}, Llyiahf/vczjk/c6a;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;)V

    const-string v3, "<this>"

    invoke-static {v8, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v2, Llyiahf/vczjk/hv3;->OooO0O0:Ljava/lang/String;

    if-eqz v3, :cond_16

    new-instance v3, Llyiahf/vczjk/o000OO;

    const/16 v10, 0x19

    invoke-direct {v3, v2, v10}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-static {v8, v11, v3}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    move-object v10, v3

    :goto_e
    move v4, v0

    goto :goto_f

    :cond_16
    move-object v10, v8

    goto :goto_e

    :goto_f
    new-instance v0, Llyiahf/vczjk/g81;

    move-object v3, v6

    move-object v6, v5

    move-object v5, v3

    move-object/from16 v3, p4

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/g81;-><init>(Ljava/lang/Object;Llyiahf/vczjk/hv3;Llyiahf/vczjk/k43;ILlyiahf/vczjk/a91;Llyiahf/vczjk/qs5;)V

    const v1, -0x3603b309

    invoke-static {v1, v0, v14}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v13

    const/4 v11, 0x0

    const/4 v12, 0x1

    const/16 v15, 0xd80

    const/16 v16, 0x2

    invoke-static/range {v10 .. v16}, Llyiahf/vczjk/dn8;->OooOOOo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;ZLlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_10
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_17

    new-instance v0, Llyiahf/vczjk/vz;

    move-object/from16 v1, p0

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object v2, v7

    move-object v3, v8

    move v7, v9

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/vz;-><init>(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/hv3;Llyiahf/vczjk/k43;Llyiahf/vczjk/a91;I)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_17
    return-void
.end method
