.class public abstract Llyiahf/vczjk/wl8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:Llyiahf/vczjk/h1a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const/16 v0, 0x16

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/wl8;->OooO00o:F

    sget-object v0, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    const/16 v1, 0x12c

    const/4 v2, 0x0

    const/4 v3, 0x2

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wl8;->OooO0O0:Llyiahf/vczjk/h1a;

    return-void
.end method

.method public static final OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/am8;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/zl8;
    .locals 15

    move-object/from16 v4, p1

    move/from16 v6, p4

    const/4 v7, 0x1

    and-int/lit8 v0, p5, 0x1

    const/4 v8, 0x0

    if-eqz v0, :cond_0

    move v1, v8

    goto :goto_0

    :cond_0
    move v1, p0

    :goto_0
    sget-object p0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    and-int/lit8 v0, p5, 0x8

    if-eqz v0, :cond_1

    move v5, v8

    goto :goto_1

    :cond_1
    move v5, v7

    :goto_1
    sget v0, Llyiahf/vczjk/nf0;->OooO0Oo:F

    sget v2, Llyiahf/vczjk/nf0;->OooO0o0:F

    sget-object v3, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    move-object/from16 v12, p3

    check-cast v12, Llyiahf/vczjk/zf1;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/f62;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_2

    if-ne v10, p0, :cond_3

    :cond_2
    new-instance v10, Llyiahf/vczjk/tl8;

    invoke-direct {v10, v3, v0, v8}, Llyiahf/vczjk/tl8;-><init>(Llyiahf/vczjk/f62;FI)V

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v9

    or-int/2addr v0, v9

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v0, :cond_4

    if-ne v9, p0, :cond_5

    :cond_4
    new-instance v9, Llyiahf/vczjk/tl8;

    invoke-direct {v9, v3, v2, v7}, Llyiahf/vczjk/tl8;-><init>(Llyiahf/vczjk/f62;FI)V

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/le3;

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    filled-new-array {v0, v4, v2}, [Ljava/lang/Object;

    move-result-object v9

    new-instance v11, Llyiahf/vczjk/jm4;

    const/16 v0, 0x17

    invoke-direct {v11, v0}, Llyiahf/vczjk/jm4;-><init>(I)V

    new-instance v0, Llyiahf/vczjk/xl8;

    move-object v2, v10

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/xl8;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Z)V

    sget-object v10, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance v10, Llyiahf/vczjk/era;

    invoke-direct {v10, v11, v0}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    and-int/lit8 v0, v6, 0xe

    xor-int/lit8 v0, v0, 0x6

    const/4 v11, 0x4

    if-le v0, v11, :cond_6

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-nez v0, :cond_7

    :cond_6
    and-int/lit8 v0, v6, 0x6

    if-ne v0, v11, :cond_8

    :cond_7
    move v0, v7

    goto :goto_2

    :cond_8
    move v0, v8

    :goto_2
    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v0, v11

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v0, v11

    and-int/lit16 v11, v6, 0x380

    xor-int/lit16 v11, v11, 0x180

    const/16 v13, 0x100

    if-le v11, v13, :cond_9

    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->ordinal()I

    move-result v11

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v11

    if-nez v11, :cond_b

    :cond_9
    and-int/lit16 v6, v6, 0x180

    if-ne v6, v13, :cond_a

    goto :goto_3

    :cond_a
    move v7, v8

    :cond_b
    :goto_3
    or-int/2addr v0, v7

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_c

    if-ne v6, p0, :cond_d

    :cond_c
    new-instance v0, Llyiahf/vczjk/ul8;

    move v6, v5

    move-object v5, v4

    move-object/from16 v4, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ul8;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/am8;Llyiahf/vczjk/oe3;Z)V

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v6, v0

    :cond_d
    move-object v11, v6

    check-cast v11, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    const/4 v14, 0x4

    invoke-static/range {v9 .. v14}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/zl8;

    return-object p0
.end method
