.class public abstract Llyiahf/vczjk/vt6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eia;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 22

    move-object/from16 v1, p0

    move-object/from16 v4, p3

    move/from16 v7, p7

    const-string v0, "chartItems"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v11, p6

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, -0x7330b3c8

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v7, 0x6

    if-nez v0, :cond_1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v7

    goto :goto_1

    :cond_1
    move v0, v7

    :goto_1
    and-int/lit8 v2, v7, 0x30

    if-nez v2, :cond_3

    move-object/from16 v2, p1

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    const/16 v3, 0x20

    goto :goto_2

    :cond_2
    const/16 v3, 0x10

    :goto_2
    or-int/2addr v0, v3

    goto :goto_3

    :cond_3
    move-object/from16 v2, p1

    :goto_3
    and-int/lit16 v3, v7, 0x180

    move/from16 v15, p2

    if-nez v3, :cond_5

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-eqz v3, :cond_4

    const/16 v3, 0x100

    goto :goto_4

    :cond_4
    const/16 v3, 0x80

    :goto_4
    or-int/2addr v0, v3

    :cond_5
    and-int/lit16 v3, v7, 0xc00

    if-nez v3, :cond_7

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_6

    const/16 v3, 0x800

    goto :goto_5

    :cond_6
    const/16 v3, 0x400

    :goto_5
    or-int/2addr v0, v3

    :cond_7
    and-int/lit16 v3, v7, 0x6000

    move-object/from16 v5, p4

    if-nez v3, :cond_9

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8

    const/16 v3, 0x4000

    goto :goto_6

    :cond_8
    const/16 v3, 0x2000

    :goto_6
    or-int/2addr v0, v3

    :cond_9
    const/high16 v3, 0x30000

    and-int/2addr v3, v7

    move-object/from16 v6, p5

    if-nez v3, :cond_b

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_a

    const/high16 v3, 0x20000

    goto :goto_7

    :cond_a
    const/high16 v3, 0x10000

    :goto_7
    or-int/2addr v0, v3

    :cond_b
    const v3, 0x12493

    and-int/2addr v0, v3

    const v3, 0x12492

    if-ne v0, v3, :cond_d

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_c

    goto :goto_8

    :cond_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_d
    :goto_8
    invoke-static {v4}, Llyiahf/vczjk/mc4;->Ooooo0o(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v14

    new-instance v0, Llyiahf/vczjk/gl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v8, 0x0

    iput-wide v8, v0, Llyiahf/vczjk/gl7;->element:J

    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    move-result v3

    int-to-float v3, v3

    const/high16 v8, 0x3f800000    # 1.0f

    mul-float/2addr v3, v8

    const/high16 v9, 0x43b40000    # 360.0f

    sub-float v3, v9, v3

    const v9, 0x6e3c21fe

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v10, :cond_e

    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v9}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v9

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v9, Llyiahf/vczjk/qs5;

    const/4 v12, 0x0

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/Boolean;

    invoke-virtual {v13}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v13

    if-nez v13, :cond_f

    const/4 v8, 0x0

    :cond_f
    const/16 v13, 0x3e8

    move-object/from16 p6, v10

    const/4 v10, 0x0

    move-object/from16 v17, v0

    const/4 v0, 0x6

    invoke-static {v13, v12, v10, v0}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v0

    const/16 v13, 0x1c

    move-object/from16 v16, v10

    move/from16 v18, v12

    const/16 v12, 0x30

    move-object v2, v9

    move-object v9, v0

    move-object/from16 v0, p6

    move/from16 p6, v3

    move-object/from16 v3, v16

    invoke-static/range {v8 .. v13}, Llyiahf/vczjk/ti;->OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v8

    const v9, 0x4c5de2

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v0, :cond_10

    new-instance v9, Llyiahf/vczjk/tt6;

    invoke-direct {v9, v2, v3}, Llyiahf/vczjk/tt6;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v9, Llyiahf/vczjk/ze3;

    const/4 v0, 0x0

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v14, v11, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    new-instance v16, Llyiahf/vczjk/ut6;

    const/16 v21, 0x0

    move-object/from16 v20, v5

    move-object/from16 v18, v6

    move-object/from16 v19, v14

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/ut6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v2, v16

    invoke-static {v1, v4, v2}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v2

    new-instance v12, Llyiahf/vczjk/rt6;

    move-object/from16 v16, p1

    move-object/from16 v18, v8

    move-object/from16 v13, v17

    move/from16 v17, p6

    invoke-direct/range {v12 .. v18}, Llyiahf/vczjk/rt6;-><init>(Llyiahf/vczjk/gl7;Ljava/util/ArrayList;FLlyiahf/vczjk/wr0;FLlyiahf/vczjk/p29;)V

    invoke-static {v2, v12, v11, v0}, Llyiahf/vczjk/vc6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_11

    new-instance v0, Llyiahf/vczjk/st6;

    move-object/from16 v2, p1

    move/from16 v3, p2

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/st6;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_11
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/s67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    const p2, -0x2c189a41

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v4, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/16 v0, 0x20

    goto :goto_1

    :cond_1
    const/16 v0, 0x10

    :goto_1
    or-int/2addr p2, v0

    and-int/lit8 v0, p2, 0x13

    const/16 v1, 0x12

    if-ne v0, v1, :cond_3

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, p1

    goto :goto_3

    :cond_3
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/s67;->OooO0oO:Llyiahf/vczjk/mw;

    shl-int/lit8 p2, p2, 0x3

    and-int/lit16 v5, p2, 0x380

    iget-object v1, p0, Llyiahf/vczjk/s67;->OooO0oo:Ljava/util/List;

    const/4 v3, 0x0

    const/16 v6, 0x8

    move-object v2, p1

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance p2, Llyiahf/vczjk/e2;

    const/16 v0, 0x18

    invoke-direct {p2, p0, v2, p3, v0}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object p2, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0O0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "setExpand"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v13, p3

    check-cast v13, Llyiahf/vczjk/zf1;

    const v0, -0xec5b0d7

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    const/4 v4, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v4

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v0, v0, 0x93

    const/16 v5, 0x92

    if-ne v0, v5, :cond_4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_4
    :goto_3
    int-to-float v10, v4

    new-instance v0, Llyiahf/vczjk/s57;

    const/4 v4, 0x0

    invoke-direct {v0, v3, v2, v1, v4}, Llyiahf/vczjk/s57;-><init>(Llyiahf/vczjk/oe3;ZII)V

    const v4, 0x1825822e

    invoke-static {v4, v0, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    const-wide/16 v8, 0x0

    const/4 v11, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    const v14, 0xc06000

    const/16 v15, 0x6f

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_5

    new-instance v0, Llyiahf/vczjk/j57;

    const/4 v5, 0x2

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/j57;-><init>(IZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0OO(ZLlyiahf/vczjk/rf1;I)V
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    const p1, 0x530e8ace

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result p1

    const/4 v0, 0x2

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    or-int/2addr p1, p2

    and-int/lit8 p1, p1, 0x3

    if-ne p1, v0, :cond_2

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_2
    :goto_1
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v0, 0x18

    int-to-float v0, v0

    invoke-static {p1, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    if-eqz p0, :cond_3

    sget p1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_arrow_drop_down_fill:I

    goto :goto_2

    :cond_3
    sget p1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_arrow_drop_up_fill:I

    :goto_2
    invoke-static {p1, v5}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v0

    const-string v1, ""

    const-wide/16 v3, 0x0

    const/16 v6, 0x1b0

    const/16 v7, 0x8

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance v0, Llyiahf/vczjk/m57;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/m57;-><init>(ZI)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0Oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 4

    const-string v0, "appState"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, -0x3e1287cd

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p2

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    const/4 v0, 0x0

    iget-object v2, p0, Ltornaco/apps/thanox/running/RunningAppState;->OooOOo0:Ljava/lang/String;

    const/4 v3, 0x0

    invoke-static {v0, v1, v2, p1, v3}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_3

    new-instance v0, Llyiahf/vczjk/k57;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p2, v1}, Llyiahf/vczjk/k57;-><init>(Ltornaco/apps/thanox/running/RunningAppState;II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooO0o(IILlyiahf/vczjk/rf1;)V
    .locals 12

    move-object v9, p2

    check-cast v9, Llyiahf/vczjk/zf1;

    const p2, -0x6d2add84

    invoke-virtual {v9, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result p2

    const/4 v0, 0x2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    or-int/2addr p2, p1

    and-int/lit8 p2, p2, 0x3

    if-ne p2, v0, :cond_2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    int-to-float v6, v0

    new-instance p2, Llyiahf/vczjk/t57;

    invoke-direct {p2, p0}, Llyiahf/vczjk/t57;-><init>(I)V

    const v0, 0x5a45d241

    invoke-static {v0, p2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    const-wide/16 v4, 0x0

    const/4 v7, 0x0

    const/4 v0, 0x0

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const v10, 0xc06000

    const/16 v11, 0x6f

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_3

    new-instance v0, Llyiahf/vczjk/nl4;

    const/4 v1, 0x1

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/nl4;-><init>(III)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooO0o0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p3

    const-string v3, "appInfo"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "onItemClick"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, 0x30d9a667

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    const/4 v5, 0x2

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    move v4, v5

    :goto_0
    or-int/2addr v4, v2

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v7, 0x10

    const/16 v8, 0x20

    if-eqz v6, :cond_1

    move v6, v8

    goto :goto_1

    :cond_1
    move v6, v7

    :goto_1
    or-int/2addr v4, v6

    and-int/lit8 v6, v4, 0x13

    const/16 v9, 0x12

    if-ne v6, v9, :cond_3

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_8

    :cond_3
    :goto_2
    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v9, -0x615d173a

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v9, v4, 0x70

    const/4 v10, 0x0

    if-ne v9, v8, :cond_4

    const/4 v8, 0x1

    goto :goto_3

    :cond_4
    move v8, v10

    :goto_3
    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_5

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v8, :cond_6

    :cond_5
    new-instance v9, Llyiahf/vczjk/l57;

    const/4 v8, 0x1

    invoke-direct {v9, v1, v0, v8}, Llyiahf/vczjk/l57;-><init>(Llyiahf/vczjk/oe3;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v9}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v9, v10}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v12, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v3, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_7

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v11, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_9

    :cond_8
    invoke-static {v12, v3, v12, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v8, 0x3f800000    # 1.0f

    invoke-static {v6, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    int-to-float v7, v7

    const/4 v11, 0x0

    invoke-static {v8, v7, v11, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/16 v8, 0x40

    int-to-float v8, v8

    invoke-static {v7, v8, v11, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v12, 0x36

    invoke-static {v7, v8, v3, v12}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v7

    iget v11, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v3, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v16, v4

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_a

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    invoke-static {v7, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_b

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_c

    :cond_b
    invoke-static {v11, v3, v11, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    invoke-static {v5, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v5, 0x36

    invoke-static {v4, v8, v3, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_d

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_d
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v4, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_e

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_f

    :cond_e
    invoke-static {v5, v3, v5, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    invoke-static {v8, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v4, 0x26

    int-to-float v4, v4

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    shl-int/lit8 v5, v16, 0x3

    and-int/lit8 v5, v5, 0x70

    const/4 v7, 0x6

    or-int/2addr v5, v7

    invoke-static {v4, v0, v3, v5}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v4, 0xc

    int-to-float v4, v4

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v4, v5, v3, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_10

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_10
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v4, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_12

    :cond_11
    invoke-static {v5, v3, v5, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_12
    invoke-static {v11, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v4, 0xdc

    int-to-float v4, v4

    const/16 v5, 0xb

    const/4 v8, 0x0

    invoke-static {v6, v8, v8, v4, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v5

    const-string v6, "getAppLabel(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v6, 0x0

    invoke-static {v7, v6, v5, v3, v4}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v4, 0x1

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v3

    if-eqz v3, :cond_13

    new-instance v4, Llyiahf/vczjk/n57;

    const/4 v5, 0x1

    invoke-direct {v4, v0, v1, v2, v5}, Llyiahf/vczjk/n57;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/oe3;II)V

    iput-object v4, v3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_13
    return-void
.end method

.method public static final OooO0oO(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 26

    move-object/from16 v0, p0

    move/from16 v1, p2

    const-string v2, "appState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x1849d7d0

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v22, v2

    goto :goto_2

    :cond_2
    :goto_1
    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->running_processes_item_description_p_s:I

    iget-object v4, v0, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v0}, Ltornaco/apps/thanox/running/RunningAppState;->OooO00o()I

    move-result v5

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    filled-new-array {v4, v5}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xc

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    const/16 v21, 0x0

    const/16 v23, 0x6000

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v24, 0x0

    const v25, 0x3ffee

    move-object/from16 v22, v2

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_2
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_3

    new-instance v3, Llyiahf/vczjk/k57;

    const/4 v4, 0x1

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/k57;-><init>(Ltornaco/apps/thanox/running/RunningAppState;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooO0oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 26

    move-object/from16 v0, p0

    move/from16 v1, p2

    const-string v2, "appState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, 0x16a2e25f

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v22, v2

    goto :goto_2

    :cond_2
    :goto_1
    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->running_processes_item_description_p:I

    iget-object v4, v0, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xc

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    const/16 v21, 0x0

    const/16 v23, 0x6000

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v24, 0x0

    const v25, 0x3ffee

    move-object/from16 v22, v2

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_2
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_3

    new-instance v3, Llyiahf/vczjk/k57;

    const/4 v4, 0x2

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/k57;-><init>(Ltornaco/apps/thanox/running/RunningAppState;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 13

    const-string v0, "onBackPressed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    const p1, -0x3faa202d

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    const/4 v0, 0x2

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    or-int/2addr p1, p2

    and-int/lit8 v1, p1, 0x3

    if-ne v1, v0, :cond_2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v5, p0

    goto/16 :goto_3

    :cond_2
    :goto_1
    sget v0, Llyiahf/vczjk/im4;->OooO0OO:I

    invoke-static {v0, v10}, Llyiahf/vczjk/so8;->OooOo0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v5

    const v0, 0x70b323c8

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v10}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v0

    if-eqz v0, :cond_d

    invoke-static {v0, v10}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v1

    const v2, 0x671a9c9b

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v2, v0, Llyiahf/vczjk/om3;

    if-eqz v2, :cond_3

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/om3;

    invoke-interface {v2}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v2

    goto :goto_2

    :cond_3
    sget-object v2, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_2
    const-class v3, Llyiahf/vczjk/a77;

    invoke-static {v3, v0, v1, v2, v10}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/a77;

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v0

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    const v2, -0x615d173a

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v8, 0x0

    if-nez v4, :cond_4

    if-ne v6, v7, :cond_5

    :cond_4
    new-instance v6, Llyiahf/vczjk/u57;

    invoke-direct {v6, v3, v0, v8}, Llyiahf/vczjk/u57;-><init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/ky4;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v6, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v10, v6}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v0, v3, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v0

    invoke-static {v0, v10}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v4

    const v0, 0x4c5de2

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v6, :cond_6

    if-ne v9, v7, :cond_7

    :cond_6
    new-instance v9, Llyiahf/vczjk/w57;

    invoke-direct {v9, v3, v8}, Llyiahf/vczjk/w57;-><init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v10, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object v6, v7

    invoke-static {v10}, Llyiahf/vczjk/xr6;->OooOOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/hb8;

    move-result-object v7

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v2, v9

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v2, :cond_8

    if-ne v9, v6, :cond_9

    :cond_8
    new-instance v9, Llyiahf/vczjk/y57;

    invoke-direct {v9, v7, v3, v8}, Llyiahf/vczjk/y57;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/a77;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v7, v10, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v7}, Llyiahf/vczjk/hb8;->OooO0OO()Z

    move-result v2

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v0, :cond_a

    if-ne v8, v6, :cond_b

    :cond_a
    new-instance v8, Llyiahf/vczjk/n20;

    const/16 v0, 0xa

    invoke-direct {v8, v7, v0}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v10, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v8, v10, v1, v1}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object v0, Llyiahf/vczjk/ob1;->OooO00o:Llyiahf/vczjk/a91;

    new-instance v1, Llyiahf/vczjk/r6;

    const/16 v2, 0x10

    invoke-direct {v1, v2, v5, v7}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v2, 0x67aded55

    invoke-static {v2, v1, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    new-instance v1, Llyiahf/vczjk/b6;

    const/16 v2, 0x1d

    invoke-direct {v1, v2, v5, v3}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v2, -0x7bf048e6

    invoke-static {v2, v1, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    new-instance v1, Llyiahf/vczjk/n6;

    const/16 v2, 0x11

    const/4 v6, 0x0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/n6;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    const v2, 0x5621494

    invoke-static {v2, v1, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    shl-int/lit8 p1, p1, 0xc

    const v2, 0xe000

    and-int/2addr p1, v2

    const v2, 0x60301b0

    or-int v11, p1, v2

    const/4 v4, 0x0

    move-object v3, v8

    const/4 v8, 0x0

    move-object v6, v9

    move-object v9, v1

    const/4 v1, 0x0

    const/16 v12, 0x89

    move-object v5, p0

    move-object v2, v0

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p0

    if-eqz p0, :cond_c

    new-instance p1, Llyiahf/vczjk/o20;

    const/4 v0, 0x7

    invoke-direct {p1, p2, v0, v5}, Llyiahf/vczjk/o20;-><init>(IILlyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void

    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOO0O(Ltornaco/apps/thanox/running/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 20

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "appState"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemClick"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v11, p3

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, -0x6c7a7706

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v4, 0x4

    if-eqz v0, :cond_0

    move v0, v4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v6, 0x10

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    move v5, v6

    :goto_1
    or-int/2addr v0, v5

    const/4 v13, 0x0

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v7, 0x800

    if-eqz v5, :cond_3

    move v5, v7

    goto :goto_3

    :cond_3
    const/16 v5, 0x400

    :goto_3
    or-int/2addr v0, v5

    and-int/lit16 v5, v0, 0x493

    const/16 v8, 0x492

    if-ne v5, v8, :cond_5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v9, v11

    goto/16 :goto_10

    :cond_5
    :goto_4
    sget-object v14, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v5, -0x615d173a

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v5, v0, 0x1c00

    const/4 v8, 0x0

    if-ne v5, v7, :cond_6

    const/4 v5, 0x1

    goto :goto_5

    :cond_6
    move v5, v8

    :goto_5
    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v5, v7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_7

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v5, :cond_8

    :cond_7
    new-instance v7, Llyiahf/vczjk/oo0oO0;

    const/16 v5, 0x1d

    invoke-direct {v7, v5, v3, v1}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v14, v7}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v7, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v11, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_9

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v11, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_a

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v8, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_b

    :cond_a
    invoke-static {v9, v11, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-static {v14, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    int-to-float v6, v6

    int-to-float v4, v4

    invoke-static {v5, v6, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v5, 0x40

    int-to-float v5, v5

    const/4 v8, 0x0

    const/4 v9, 0x2

    invoke-static {v4, v5, v8, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v9, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v8, 0x36

    invoke-static {v5, v9, v11, v8}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v8, v11, Llyiahf/vczjk/zf1;->Oooo:I

    move/from16 v17, v0

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v0

    invoke-static {v11, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v3, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v3, :cond_c

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v5, v11, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v0, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_d

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e

    :cond_d
    invoke-static {v8, v11, v8, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v4, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v3, 0x36

    invoke-static {v0, v9, v11, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v11, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_f

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_f
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v4, v11, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_10

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11

    :cond_10
    invoke-static {v5, v11, v5, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    invoke-static {v3, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x26

    int-to-float v2, v2

    invoke-static {v14, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v1, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v4, 0x6

    invoke-static {v2, v3, v11, v4}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v2, 0xc

    int-to-float v2, v2

    invoke-static {v14, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v11, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v2, v5, v11, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v8, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    move-object/from16 v18, v3

    invoke-static {v11, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v19, v2

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_12

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_12
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v5, v11, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_13

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_14

    :cond_13
    invoke-static {v8, v11, v8, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    invoke-static {v3, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x30

    invoke-static {v0, v9, v11, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v2, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v11, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_15

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_a

    :cond_15
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_a
    invoke-static {v0, v11, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v3, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_16

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_17

    :cond_16
    invoke-static {v2, v11, v2, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_17
    invoke-static {v4, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v0, 0xf0

    int-to-float v0, v0

    const/16 v2, 0xb

    const/4 v3, 0x0

    invoke-static {v14, v3, v3, v0, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual/range {v18 .. v18}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v2

    const-string v3, "getAppLabel(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x0

    const/4 v4, 0x6

    invoke-static {v4, v3, v2, v11, v0}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v0, -0x14109ae9

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v0, v1, Ltornaco/apps/thanox/running/RunningAppState;->OooOOoo:Z

    if-eqz v0, :cond_18

    invoke-static {v3, v11}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-static {v14, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget v0, Lgithub/tornaco/android/thanos/lite/app/R$drawable;->ic_rocket_line:I

    invoke-static {v0, v11}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v4

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-wide v8, v0, Llyiahf/vczjk/x21;->OooO00o:J

    move-object v0, v7

    move-wide v7, v8

    move-object v9, v11

    const/4 v11, 0x0

    const-string v5, "Playing"

    move-object v2, v10

    const/16 v10, 0x1b0

    invoke-static/range {v4 .. v11}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    goto :goto_b

    :cond_18
    move-object v0, v7

    move-object v2, v10

    move-object v9, v11

    :goto_b
    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x1

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1}, Ltornaco/apps/thanox/running/RunningAppState;->OooO00o()I

    move-result v4

    if-nez v4, :cond_19

    const v4, 0x624e3fed

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v4, v17, 0xe

    invoke-static {v1, v9, v4}, Llyiahf/vczjk/vt6;->OooO0oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_c
    const/4 v4, 0x1

    goto :goto_d

    :cond_19
    const v4, 0x624f4b6c

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v4, v17, 0xe

    invoke-static {v1, v9, v4}, Llyiahf/vczjk/vt6;->OooO0oO(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_c

    :goto_d
    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v4, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    move-object/from16 v6, v19

    const/16 v5, 0x36

    invoke-static {v6, v4, v9, v5}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v9, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_1a

    invoke-virtual {v9, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_e

    :cond_1a
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_e
    invoke-static {v4, v9, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v9, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_1b

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1c

    :cond_1b
    invoke-static {v5, v9, v5, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    invoke-static {v7, v9, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    and-int/lit8 v0, v17, 0xe

    invoke-static {v1, v9, v0}, Llyiahf/vczjk/vt6;->OooO0Oo(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/rf1;I)V

    const v0, 0x79960c7c

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez p1, :cond_1d

    move-object/from16 v2, p1

    goto :goto_f

    :cond_1d
    invoke-static {v3, v9}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "CPU "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    move-object/from16 v2, p1

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, "%"

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v5, 0x2

    const/4 v6, 0x0

    invoke-static {v3, v5, v0, v9, v6}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_f
    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v9}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    new-instance v0, Llyiahf/vczjk/iv5;

    const/4 v3, 0x1

    invoke-direct {v0, v3}, Llyiahf/vczjk/iv5;-><init>(I)V

    const v3, -0x2fee37be

    invoke-static {v3, v0, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    const/4 v8, 0x0

    move-object v11, v9

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const v12, 0x180006

    const/16 v13, 0x1e

    invoke-static/range {v4 .. v13}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object v9, v11

    const/4 v4, 0x1

    invoke-static {v9, v4, v4, v4}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_10
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_1e

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/16 v5, 0xb

    move-object/from16 v3, p2

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1e
    return-void
.end method

.method public static final OooOO0o(Llyiahf/vczjk/dw4;Llyiahf/vczjk/s67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v1, p1

    move-object/from16 v3, p2

    move-object/from16 v5, p4

    move-object/from16 v4, p5

    move-object/from16 v7, p6

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const-string v2, "state"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "onRunningItemClick"

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "onNotRunningItemClick"

    move-object/from16 v6, p3

    invoke-static {v6, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "onFilterItemSelected"

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "setRunningExpand"

    invoke-static {v4, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "setCachedExpand"

    invoke-static {v7, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v13, p7

    check-cast v13, Llyiahf/vczjk/zf1;

    const v2, 0x59d132af

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit8 v2, p8, 0x10

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_0

    const/16 v8, 0x100

    goto :goto_0

    :cond_0
    const/16 v8, 0x80

    :goto_0
    or-int/2addr v2, v8

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    const/16 v9, 0x800

    if-eqz v8, :cond_1

    move v8, v9

    goto :goto_1

    :cond_1
    const/16 v8, 0x400

    :goto_1
    or-int/2addr v2, v8

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    const/high16 v10, 0x20000

    if-eqz v8, :cond_2

    move v8, v10

    goto :goto_2

    :cond_2
    const/high16 v8, 0x10000

    :goto_2
    or-int/2addr v2, v8

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    const/high16 v8, 0x100000

    goto :goto_3

    :cond_3
    const/high16 v8, 0x80000

    :goto_3
    or-int/2addr v2, v8

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_4

    const/high16 v8, 0x800000

    goto :goto_4

    :cond_4
    const/high16 v8, 0x400000

    :goto_4
    or-int/2addr v2, v8

    const v8, 0x492493

    and-int/2addr v8, v2

    const v14, 0x492492

    if-ne v8, v14, :cond_6

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    goto/16 :goto_c

    :cond_6
    :goto_5
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v8, p8, 0x1

    const/4 v14, 0x0

    if-eqz v8, :cond_8

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v8

    if-eqz v8, :cond_7

    goto :goto_6

    :cond_7
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v2, v2, -0x71

    move-object/from16 v8, p0

    goto :goto_7

    :cond_8
    :goto_6
    const/4 v8, 0x3

    invoke-static {v14, v8, v13}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v8

    and-int/lit8 v2, v2, -0x71

    :goto_7
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget v15, Llyiahf/vczjk/im4;->OooO0OO:I

    invoke-static {v15, v13}, Llyiahf/vczjk/so8;->OooOo0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v15

    sget-object v14, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/x21;

    iget-wide v11, v14, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v14, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v0, v11, v12, v14}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v11, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v0, v11}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const/16 v0, 0x60

    int-to-float v0, v0

    const/4 v12, 0x7

    const/4 v14, 0x0

    invoke-static {v14, v14, v14, v0, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v12

    const v0, -0x48fade91

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v0, v14

    const/high16 v14, 0x70000

    and-int/2addr v14, v2

    const/16 v16, 0x1

    if-ne v14, v10, :cond_9

    move/from16 v10, v16

    goto :goto_8

    :cond_9
    const/4 v10, 0x0

    :goto_8
    or-int/2addr v0, v10

    const/high16 v10, 0x380000

    and-int/2addr v10, v2

    const/high16 v14, 0x100000

    if-ne v10, v14, :cond_a

    move/from16 v10, v16

    goto :goto_9

    :cond_a
    const/4 v10, 0x0

    :goto_9
    or-int/2addr v0, v10

    and-int/lit16 v10, v2, 0x1c00

    if-ne v10, v9, :cond_b

    move/from16 v9, v16

    goto :goto_a

    :cond_b
    const/4 v9, 0x0

    :goto_a
    or-int/2addr v0, v9

    const/high16 v9, 0x1c00000

    and-int/2addr v2, v9

    const/high16 v9, 0x800000

    if-ne v2, v9, :cond_c

    goto :goto_b

    :cond_c
    const/16 v16, 0x0

    :goto_b
    or-int v0, v0, v16

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_d

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v0, :cond_e

    :cond_d
    new-instance v0, Llyiahf/vczjk/qv5;

    move-object v2, v5

    move-object v5, v3

    move-object v3, v2

    move-object v2, v7

    move-object v7, v6

    move-object v6, v2

    move-object v2, v15

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/qv5;-><init>(Llyiahf/vczjk/s67;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v2, v0

    :cond_e
    check-cast v2, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x0

    move-object v3, v11

    const/4 v11, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v4, v8

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/16 v14, 0x180

    const/16 v15, 0x1f8

    move-object v5, v12

    move-object v12, v2

    invoke-static/range {v3 .. v15}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object v1, v4

    :goto_c
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_f

    new-instance v0, Llyiahf/vczjk/q57;

    const/4 v9, 0x0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move/from16 v8, p8

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/q57;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;Llyiahf/vczjk/cf3;II)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooOOO(Llyiahf/vczjk/vw;Ljava/util/List;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V
    .locals 30

    move-object/from16 v1, p1

    move-object/from16 v2, p3

    const-string v0, "selectedItem"

    move-object/from16 v7, p0

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "allItems"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "setReverse"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v12, p6

    check-cast v12, Llyiahf/vczjk/zf1;

    const v0, -0x65631452

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    const/4 v3, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    or-int v0, p7, v0

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    const/16 v4, 0x10

    :goto_1
    or-int/2addr v0, v4

    move/from16 v5, p2

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x800

    goto :goto_3

    :cond_3
    const/16 v4, 0x400

    :goto_3
    or-int/2addr v0, v4

    move-object/from16 v4, p4

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_4

    const/16 v8, 0x4000

    goto :goto_4

    :cond_4
    const/16 v8, 0x2000

    :goto_4
    or-int/2addr v0, v8

    move/from16 v14, p5

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    if-eqz v8, :cond_5

    const/high16 v8, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v8, 0x10000

    :goto_5
    or-int/2addr v0, v8

    const v8, 0x12493

    and-int/2addr v8, v0

    const v9, 0x12492

    if-ne v8, v9, :cond_8

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_6

    goto :goto_6

    :cond_6
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_7
    move-object v15, v12

    goto/16 :goto_9

    :cond_8
    :goto_6
    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v9

    if-nez v9, :cond_7

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v10, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v9, v10, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo00(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ub0;I)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v9, 0x0

    invoke-static {v10, v9}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v11, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v12, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_9

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_9
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_a

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v10, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_b

    :cond_a
    invoke-static {v11, v12, v11, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x6e3c21fe

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v8, :cond_c

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v3

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7}, Llyiahf/vczjk/vw;->OooO00o()I

    move-result v6

    invoke-static {v6, v12}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    sget-object v10, Llyiahf/vczjk/mt6;->OooO0OO:Llyiahf/vczjk/qv3;

    if-eqz v10, :cond_d

    goto/16 :goto_8

    :cond_d
    new-instance v18, Llyiahf/vczjk/pv3;

    const-wide/16 v24, 0x0

    const/16 v28, 0x60

    const-string v19, "Filled.Sort"

    const/high16 v20, 0x41c00000    # 24.0f

    const/high16 v21, 0x41c00000    # 24.0f

    const/high16 v22, 0x41c00000    # 24.0f

    const/high16 v23, 0x41c00000    # 24.0f

    const/16 v26, 0x0

    const/16 v27, 0x0

    invoke-direct/range {v18 .. v28}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    move-object/from16 v10, v18

    sget v11, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v11, Llyiahf/vczjk/gx8;

    sget-wide v9, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v11, v9, v10}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v9, Llyiahf/vczjk/jq;

    const/4 v10, 0x1

    invoke-direct {v9, v10}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v10, 0x40400000    # 3.0f

    const/high16 v13, 0x41900000    # 18.0f

    invoke-virtual {v9, v10, v13}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v15, 0x40c00000    # 6.0f

    invoke-virtual {v9, v15}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v13, -0x40000000    # -2.0f

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v13, 0x41800000    # 16.0f

    invoke-virtual {v9, v10, v13}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v13, 0x40000000    # 2.0f

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v9, v10, v15}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v13, 0x41900000    # 18.0f

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v13, 0x41a80000    # 21.0f

    invoke-virtual {v9, v13, v15}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v9, v10, v15}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v13, 0x41500000    # 13.0f

    invoke-virtual {v9, v10, v13}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v13, 0x41400000    # 12.0f

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v13, -0x40000000    # -2.0f

    invoke-virtual {v9, v13}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v13, 0x41300000    # 11.0f

    invoke-virtual {v9, v10, v13}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v10, 0x40000000    # 2.0f

    invoke-virtual {v9, v10}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v9, v9, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    move-object/from16 v10, v18

    invoke-static {v10, v9, v11}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v10}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v10

    sput-object v10, Llyiahf/vczjk/mt6;->OooO0OO:Llyiahf/vczjk/qv3;

    :goto_8
    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    const v11, 0x4c5de2

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-ne v11, v8, :cond_e

    new-instance v11, Llyiahf/vczjk/a67;

    const/16 v8, 0xa

    invoke-direct {v11, v3, v8}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v11, Llyiahf/vczjk/le3;

    const/4 v8, 0x0

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    shl-int/lit8 v0, v0, 0x3

    const/high16 v8, 0x380000

    and-int/2addr v0, v8

    or-int/lit16 v0, v0, 0x180

    move-object v15, v12

    move-object v12, v10

    move-object v10, v11

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/16 v17, 0x28

    move/from16 v16, v0

    move-object v8, v6

    invoke-static/range {v8 .. v17}, Llyiahf/vczjk/zsa;->OooO0o0(Ljava/lang/String;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/qv3;Llyiahf/vczjk/qv3;ZLlyiahf/vczjk/rf1;II)V

    sget-object v0, Llyiahf/vczjk/cl8;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/al8;

    const/16 v6, 0x12

    int-to-float v6, v6

    invoke-static {v6}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v6

    invoke-static {v0, v6}, Llyiahf/vczjk/al8;->OooO00o(Llyiahf/vczjk/al8;Llyiahf/vczjk/tv7;)Llyiahf/vczjk/al8;

    move-result-object v9

    new-instance v0, Llyiahf/vczjk/jg0;

    move-object/from16 v29, v4

    move-object v4, v3

    move-object/from16 v3, v29

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/jg0;-><init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Z)V

    const v1, -0x600c8fdd    # -1.0310002E-19f

    invoke-static {v1, v0, v15}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/16 v13, 0xc00

    move-object v12, v15

    invoke-static/range {v8 .. v13}, Llyiahf/vczjk/we5;->OooO0OO(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    const/4 v10, 0x1

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_f

    new-instance v0, Llyiahf/vczjk/lx8;

    move-object/from16 v2, p1

    move/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p5

    move-object v1, v7

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/lx8;-><init>(Llyiahf/vczjk/vw;Ljava/util/List;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZI)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooOOO0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "setExpand"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v13, p3

    check-cast v13, Llyiahf/vczjk/zf1;

    const v0, 0x737a88ea

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    const/4 v4, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v4

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v0, v0, 0x93

    const/16 v5, 0x92

    if-ne v0, v5, :cond_4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_4
    :goto_3
    int-to-float v10, v4

    new-instance v0, Llyiahf/vczjk/s57;

    const/4 v4, 0x1

    invoke-direct {v0, v3, v2, v1, v4}, Llyiahf/vczjk/s57;-><init>(Llyiahf/vczjk/oe3;ZII)V

    const v4, 0x29f5b685

    invoke-static {v4, v0, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    const-wide/16 v8, 0x0

    const/4 v11, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    const v14, 0xc06000

    const/16 v15, 0x6f

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_5

    new-instance v0, Llyiahf/vczjk/j57;

    const/4 v5, 0x3

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/j57;-><init>(IZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/dp8;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/dp8;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    return-object v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "This is should be simple type: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOOOo(DDD)D
    .locals 1

    cmpl-double v0, p2, p4

    if-gtz v0, :cond_2

    cmpg-double v0, p0, p2

    if-gez v0, :cond_0

    return-wide p2

    :cond_0
    cmpl-double p2, p0, p4

    if-lez p2, :cond_1

    return-wide p4

    :cond_1
    return-wide p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Cannot coerce value to an empty range: maximum "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p4, p5}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    const-string p4, " is less than minimum "

    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p2, p3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    const/16 p2, 0x2e

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOOo(III)I
    .locals 2

    if-gt p1, p2, :cond_2

    if-ge p0, p1, :cond_0

    return p1

    :cond_0
    if-le p0, p2, :cond_1

    return p2

    :cond_1
    return p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot coerce value to an empty range: maximum "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p2, " is less than minimum "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 p1, 0x2e

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOOo0(FFF)F
    .locals 2

    cmpl-float v0, p1, p2

    if-gtz v0, :cond_2

    cmpg-float v0, p0, p1

    if-gez v0, :cond_0

    return p1

    :cond_0
    cmpl-float p1, p0, p2

    if-lez p1, :cond_1

    return p2

    :cond_1
    return p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot coerce value to an empty range: maximum "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string p2, " is less than minimum "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const/16 p1, 0x2e

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOOoo(ILlyiahf/vczjk/x14;)I
    .locals 2

    const-string v0, "range"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Llyiahf/vczjk/n01;

    if-eqz v0, :cond_0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    check-cast p1, Llyiahf/vczjk/n01;

    invoke-static {p0, p1}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    move-result p0

    return p0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/x14;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget v0, p1, Llyiahf/vczjk/v14;->OooOOO0:I

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    if-ge p0, v1, :cond_1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    move-result p0

    return p0

    :cond_1
    iget p1, p1, Llyiahf/vczjk/v14;->OooOOO:I

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    if-le p0, v0, :cond_2

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    move-result p0

    :cond_2
    return p0

    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot coerce value to an empty range: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p1, 0x2e

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOo(Llyiahf/vczjk/xk7;Llyiahf/vczjk/ol2;Landroid/view/View;Landroid/view/View;Landroidx/recyclerview/widget/OooOo00;Z)I
    .locals 0

    invoke-virtual {p4}, Landroidx/recyclerview/widget/OooOo00;->OooOo0o()I

    move-result p4

    if-eqz p4, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p4

    if-eqz p4, :cond_2

    if-eqz p2, :cond_2

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    if-nez p5, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p0

    return p0

    :cond_1
    invoke-virtual {p1, p3}, Llyiahf/vczjk/ol2;->OooO0O0(Landroid/view/View;)I

    move-result p4

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ol2;->OooO0o0(Landroid/view/View;)I

    move-result p1

    sub-int/2addr p4, p1

    invoke-static {p2}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p1

    invoke-static {p3}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p2

    sub-int/2addr p1, p2

    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    move-result p1

    add-int/lit8 p1, p1, 0x1

    int-to-float p2, p4

    int-to-float p1, p1

    div-float/2addr p2, p1

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p0

    int-to-float p0, p0

    mul-float/2addr p2, p0

    float-to-int p0, p2

    return p0

    :cond_2
    :goto_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;
    .locals 2

    const-string v0, "range"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/m01;

    invoke-virtual {v0}, Llyiahf/vczjk/m01;->OooO00o()Z

    move-result v1

    if-nez v1, :cond_2

    iget p1, v0, Llyiahf/vczjk/m01;->OooO00o:F

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/m01;->OooO0O0(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v0, v1, p0}, Llyiahf/vczjk/m01;->OooO0O0(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    return-object p0

    :cond_0
    iget p1, v0, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v0, v1, p0}, Llyiahf/vczjk/m01;->OooO0O0(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/m01;->OooO0O0(Ljava/lang/Comparable;Ljava/lang/Comparable;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    :cond_1
    return-object p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot coerce value to an empty range: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 p1, 0x2e

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOo00(JJJ)J
    .locals 1

    cmp-long v0, p2, p4

    if-gtz v0, :cond_2

    cmp-long v0, p0, p2

    if-gez v0, :cond_0

    return-wide p2

    :cond_0
    cmp-long p2, p0, p4

    if-lez p2, :cond_1

    return-wide p4

    :cond_1
    return-wide p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Cannot coerce value to an empty range: maximum "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p4, p5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string p4, " is less than minimum "

    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const/16 p2, 0x2e

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOo0O(Llyiahf/vczjk/xk7;Llyiahf/vczjk/ol2;Landroid/view/View;Landroid/view/View;Landroidx/recyclerview/widget/OooOo00;Z)I
    .locals 0

    invoke-virtual {p4}, Landroidx/recyclerview/widget/OooOo00;->OooOo0o()I

    move-result p4

    if-eqz p4, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p0

    if-eqz p0, :cond_2

    if-eqz p2, :cond_2

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    if-nez p5, :cond_1

    invoke-static {p2}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p0

    invoke-static {p3}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p1

    sub-int/2addr p0, p1

    invoke-static {p0}, Ljava/lang/Math;->abs(I)I

    move-result p0

    add-int/lit8 p0, p0, 0x1

    return p0

    :cond_1
    invoke-virtual {p1, p3}, Llyiahf/vczjk/ol2;->OooO0O0(Landroid/view/View;)I

    move-result p0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ol2;->OooO0o0(Landroid/view/View;)I

    move-result p2

    sub-int/2addr p0, p2

    invoke-virtual {p1}, Llyiahf/vczjk/ol2;->OooOO0o()I

    move-result p1

    invoke-static {p1, p0}, Ljava/lang/Math;->min(II)I

    move-result p0

    return p0

    :cond_2
    :goto_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOo0o(Llyiahf/vczjk/xk7;Llyiahf/vczjk/ol2;Landroid/view/View;Landroid/view/View;Landroidx/recyclerview/widget/OooOo00;ZZ)I
    .locals 3

    invoke-virtual {p4}, Landroidx/recyclerview/widget/OooOo00;->OooOo0o()I

    move-result p4

    const/4 v0, 0x0

    if-eqz p4, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p4

    if-eqz p4, :cond_3

    if-eqz p2, :cond_3

    if-nez p3, :cond_0

    goto :goto_1

    :cond_0
    invoke-static {p2}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p4

    invoke-static {p3}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result v1

    invoke-static {p4, v1}, Ljava/lang/Math;->min(II)I

    move-result p4

    invoke-static {p2}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result v1

    invoke-static {p3}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result v2

    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-eqz p6, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/xk7;->OooO0O0()I

    move-result p0

    sub-int/2addr p0, v1

    add-int/lit8 p0, p0, -0x1

    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    move-result p0

    goto :goto_0

    :cond_1
    invoke-static {v0, p4}, Ljava/lang/Math;->max(II)I

    move-result p0

    :goto_0
    if-nez p5, :cond_2

    return p0

    :cond_2
    invoke-virtual {p1, p3}, Llyiahf/vczjk/ol2;->OooO0O0(Landroid/view/View;)I

    move-result p4

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ol2;->OooO0o0(Landroid/view/View;)I

    move-result p5

    sub-int/2addr p4, p5

    invoke-static {p4}, Ljava/lang/Math;->abs(I)I

    move-result p4

    invoke-static {p2}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p5

    invoke-static {p3}, Landroidx/recyclerview/widget/OooOo00;->Oooo0O0(Landroid/view/View;)I

    move-result p3

    sub-int/2addr p5, p3

    invoke-static {p5}, Ljava/lang/Math;->abs(I)I

    move-result p3

    add-int/lit8 p3, p3, 0x1

    int-to-float p4, p4

    int-to-float p3, p3

    div-float/2addr p4, p3

    int-to-float p0, p0

    mul-float/2addr p0, p4

    invoke-virtual {p1}, Llyiahf/vczjk/ol2;->OooOO0O()I

    move-result p3

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ol2;->OooO0o0(Landroid/view/View;)I

    move-result p1

    sub-int/2addr p3, p1

    int-to-float p1, p3

    add-float/2addr p0, p1

    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    move-result p0

    return p0

    :cond_3
    :goto_1
    return v0
.end method

.method public static final OooOoO(II)I
    .locals 0

    shr-int/2addr p0, p1

    and-int/lit8 p0, p0, 0x1f

    return p0
.end method

.method public static final OooOoO0()J
    .locals 2

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Thread;->getId()J

    move-result-wide v0

    return-wide v0
.end method

.method public static final OooOoo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "newArguments"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "newAttributes"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    if-ne p2, v0, :cond_0

    return-object p0

    :cond_0
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, p2}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0

    :cond_1
    instance-of v0, p0, Llyiahf/vczjk/rq2;

    if-eqz v0, :cond_2

    check-cast p0, Llyiahf/vczjk/rq2;

    new-instance v0, Llyiahf/vczjk/rq2;

    iget-object p2, p0, Llyiahf/vczjk/rq2;->OooOOoo:[Ljava/lang/String;

    array-length v1, p2

    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    move-object v6, p2

    check-cast v6, [Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/rq2;->OooOOO:Llyiahf/vczjk/n3a;

    iget-object v2, p0, Llyiahf/vczjk/rq2;->OooOOOO:Llyiahf/vczjk/oq2;

    iget-object v3, p0, Llyiahf/vczjk/rq2;->OooOOOo:Llyiahf/vczjk/tq2;

    iget-boolean v5, p0, Llyiahf/vczjk/rq2;->OooOOo:Z

    move-object v4, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/rq2;-><init>(Llyiahf/vczjk/n3a;Llyiahf/vczjk/oq2;Llyiahf/vczjk/tq2;Ljava/util/List;Z[Ljava/lang/String;)V

    return-object v0

    :cond_2
    move-object v4, p1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result p0

    invoke-static {v4, p2, p1, p0}, Llyiahf/vczjk/so8;->Oooo0oO(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0
.end method

.method public static OooOooO(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/ko;I)Llyiahf/vczjk/uk4;
    .locals 1

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p2

    :cond_0
    const-string p3, "<this>"

    invoke-static {p0, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result p3

    if-nez p3, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p3

    if-ne p1, p3, :cond_2

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object p3

    if-ne p2, p3, :cond_2

    return-object p0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p3

    instance-of v0, p2, Llyiahf/vczjk/z03;

    if-eqz v0, :cond_3

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/z03;

    invoke-virtual {v0}, Llyiahf/vczjk/z03;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3

    sget-object p2, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    :cond_3
    invoke-static {p3, p2}, Llyiahf/vczjk/br6;->Oooo000(Llyiahf/vczjk/d3a;Llyiahf/vczjk/ko;)Llyiahf/vczjk/d3a;

    move-result-object p2

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p0

    instance-of p3, p0, Llyiahf/vczjk/k23;

    if-eqz p3, :cond_4

    check-cast p0, Llyiahf/vczjk/k23;

    iget-object p3, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-static {p3, p1, p2}, Llyiahf/vczjk/vt6;->OooOoo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p3

    iget-object p0, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/vt6;->OooOoo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p0

    invoke-static {p3, p0}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object p0

    return-object p0

    :cond_4
    instance-of p3, p0, Llyiahf/vczjk/dp8;

    if-eqz p3, :cond_5

    check-cast p0, Llyiahf/vczjk/dp8;

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/vt6;->OooOoo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0

    :cond_5
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0
.end method

.method public static synthetic OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;
    .locals 1

    and-int/lit8 v0, p3, 0x1

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p1

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p2

    :cond_1
    invoke-static {p0, p1, p2}, Llyiahf/vczjk/vt6;->OooOoo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p0

    return-object p0
.end method

.method public static final Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooOOOO(Llyiahf/vczjk/rf1;)Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static Oooo000(Llyiahf/vczjk/x14;)Llyiahf/vczjk/v14;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/v14;->OooOOOO:I

    neg-int v0, v0

    new-instance v1, Llyiahf/vczjk/v14;

    iget v2, p0, Llyiahf/vczjk/v14;->OooOOO:I

    iget p0, p0, Llyiahf/vczjk/v14;->OooOOO0:I

    invoke-direct {v1, v2, p0, v0}, Llyiahf/vczjk/v14;-><init>(III)V

    return-object v1
.end method

.method public static Oooo00O(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/qj8;I)Llyiahf/vczjk/kl5;
    .locals 9

    and-int/lit8 p3, p3, 0x4

    const/4 v0, 0x0

    if-eqz p3, :cond_1

    int-to-float p3, v0

    invoke-static {p1, p3}, Ljava/lang/Float;->compare(FF)I

    move-result p3

    if-lez p3, :cond_0

    const/4 p3, 0x1

    goto :goto_0

    :cond_0
    move p3, v0

    :goto_0
    move v4, p3

    goto :goto_1

    :cond_1
    move v4, v0

    :goto_1
    sget-wide v5, Llyiahf/vczjk/oj3;->OooO00o:J

    int-to-float p3, v0

    invoke-static {p1, p3}, Ljava/lang/Float;->compare(FF)I

    move-result p3

    if-gtz p3, :cond_3

    if-eqz v4, :cond_2

    goto :goto_2

    :cond_2
    return-object p0

    :cond_3
    :goto_2
    new-instance v1, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;

    move-wide v7, v5

    move v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v8}, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;-><init>(FLlyiahf/vczjk/qj8;ZJJ)V

    invoke-interface {p0, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static Oooo00o(ILlyiahf/vczjk/x14;)Llyiahf/vczjk/v14;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-lez p0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    if-eqz v0, :cond_2

    iget v0, p1, Llyiahf/vczjk/v14;->OooOOOO:I

    if-lez v0, :cond_1

    goto :goto_1

    :cond_1
    neg-int p0, p0

    :goto_1
    new-instance v0, Llyiahf/vczjk/v14;

    iget v1, p1, Llyiahf/vczjk/v14;->OooOOO0:I

    iget p1, p1, Llyiahf/vczjk/v14;->OooOOO:I

    invoke-direct {v0, v1, p1, p0}, Llyiahf/vczjk/v14;-><init>(III)V

    return-object v0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Step must be positive, was: "

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v0, 0x2e

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;
    .locals 1

    invoke-static {p2}, Llyiahf/vczjk/ll6;->OooOOOO(Llyiahf/vczjk/rf1;)Landroid/content/res/Resources;

    move-result-object p2

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p2, p0, p1}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final Oooo0OO(Ljava/lang/String;)V
    .locals 1

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final Oooo0o(Ljava/lang/String;)V
    .locals 1

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/NoSuchElementException;

    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final Oooo0o0(Ljava/lang/String;)V
    .locals 1

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static Oooo0oO(II)Llyiahf/vczjk/x14;
    .locals 2

    const/high16 v0, -0x80000000

    if-gt p1, v0, :cond_0

    sget-object p0, Llyiahf/vczjk/x14;->OooOOOo:Llyiahf/vczjk/x14;

    sget-object p0, Llyiahf/vczjk/x14;->OooOOOo:Llyiahf/vczjk/x14;

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/x14;

    const/4 v1, 0x1

    sub-int/2addr p1, v1

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/v14;-><init>(III)V

    return-object v0
.end method


# virtual methods
.method public abstract OooOoOO(I)V
.end method

.method public abstract OooOoo0(Landroid/graphics/Typeface;Z)V
.end method
