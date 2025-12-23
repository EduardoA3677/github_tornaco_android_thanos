.class public final Llyiahf/vczjk/nf0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/nf0;

.field public static final OooO0O0:F

.field public static final OooO0OO:F

.field public static final OooO0Oo:F

.field public static final OooO0o0:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/nf0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/nf0;->OooO00o:Llyiahf/vczjk/nf0;

    sget-object v0, Llyiahf/vczjk/sl8;->OooO00o:Llyiahf/vczjk/y21;

    sget v0, Llyiahf/vczjk/sl8;->OooO0o:F

    sput v0, Llyiahf/vczjk/nf0;->OooO0O0:F

    const/16 v0, 0x38

    int-to-float v0, v0

    const/16 v1, 0x280

    int-to-float v1, v1

    sput v1, Llyiahf/vczjk/nf0;->OooO0OO:F

    sput v0, Llyiahf/vczjk/nf0;->OooO0Oo:F

    const/16 v0, 0x7d

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/nf0;->OooO0o0:F

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hl5;FFLlyiahf/vczjk/ir1;JLlyiahf/vczjk/rf1;I)V
    .locals 21

    move/from16 v8, p8

    move-object/from16 v0, p7

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x515137eb

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit16 v1, v8, 0x25b6

    and-int/lit16 v2, v1, 0x2493

    const/16 v3, 0x2492

    const/4 v4, 0x0

    const/4 v5, 0x1

    if-eq v2, v3, :cond_0

    move v2, v5

    goto :goto_0

    :cond_0
    move v2, v4

    :goto_0
    and-int/2addr v1, v5

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v8, 0x1

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p1

    move/from16 v2, p2

    move/from16 v3, p3

    move-object/from16 v10, p4

    move-wide/from16 v11, p5

    goto :goto_2

    :cond_2
    :goto_1
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget v2, Llyiahf/vczjk/sl8;->OooO0o0:F

    sget v3, Llyiahf/vczjk/sl8;->OooO0Oo:F

    sget-object v6, Llyiahf/vczjk/cl8;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/al8;

    iget-object v6, v6, Llyiahf/vczjk/al8;->OooO0o0:Llyiahf/vczjk/ir1;

    sget-object v7, Llyiahf/vczjk/sl8;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v7, v0}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v9

    move-wide v11, v9

    move-object v10, v6

    :goto_2
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget v6, Landroidx/compose/material3/R$string;->m3c_bottom_sheet_drag_handle_description:I

    invoke-static {v6, v0}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    const/4 v7, 0x0

    sget v9, Llyiahf/vczjk/wl8;->OooO00o:F

    invoke-static {v1, v7, v9, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_3

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v7, :cond_4

    :cond_3
    new-instance v9, Llyiahf/vczjk/kf0;

    const/4 v7, 0x0

    invoke-direct {v9, v6, v7}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v5, v4, v9}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v9

    new-instance v4, Llyiahf/vczjk/mf0;

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/mf0;-><init>(FF)V

    const v5, -0x3df6a050

    invoke-static {v5, v4, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v17

    const/4 v15, 0x0

    const/16 v16, 0x0

    const-wide/16 v13, 0x0

    const/high16 v19, 0xc00000

    const/16 v20, 0x78

    move-object/from16 v18, v0

    invoke-static/range {v9 .. v20}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    move v4, v3

    move-object v5, v10

    move-wide v6, v11

    move v3, v2

    move-object v2, v1

    goto :goto_3

    :cond_5
    move-object/from16 v18, v0

    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v5, p4

    move-wide/from16 v6, p5

    :goto_3
    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_6

    new-instance v0, Llyiahf/vczjk/lf0;

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/lf0;-><init>(Llyiahf/vczjk/nf0;Llyiahf/vczjk/hl5;FFLlyiahf/vczjk/ir1;JI)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method
