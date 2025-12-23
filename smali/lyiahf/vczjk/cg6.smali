.class public final Llyiahf/vczjk/cg6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/ei9;

.field public final synthetic OooOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:Ljava/lang/String;

.field public final synthetic OooOOoo:Z

.field public final synthetic OooOo:I

.field public final synthetic OooOo0:Llyiahf/vczjk/nj4;

.field public final synthetic OooOo00:Llyiahf/vczjk/rn9;

.field public final synthetic OooOo0O:Llyiahf/vczjk/mj4;

.field public final synthetic OooOo0o:I

.field public final synthetic OooOoO:Llyiahf/vczjk/rr5;

.field public final synthetic OooOoO0:Llyiahf/vczjk/ml9;

.field public final synthetic OooOoOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOoo0:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;ZLlyiahf/vczjk/ei9;Ljava/lang/String;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;IILlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cg6;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object p2, p0, Llyiahf/vczjk/cg6;->OooOOO:Llyiahf/vczjk/a91;

    iput-boolean p3, p0, Llyiahf/vczjk/cg6;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/cg6;->OooOOOo:Llyiahf/vczjk/ei9;

    iput-object p5, p0, Llyiahf/vczjk/cg6;->OooOOo0:Ljava/lang/String;

    iput-object p6, p0, Llyiahf/vczjk/cg6;->OooOOo:Llyiahf/vczjk/oe3;

    iput-boolean p7, p0, Llyiahf/vczjk/cg6;->OooOOoo:Z

    iput-object p8, p0, Llyiahf/vczjk/cg6;->OooOo00:Llyiahf/vczjk/rn9;

    iput-object p9, p0, Llyiahf/vczjk/cg6;->OooOo0:Llyiahf/vczjk/nj4;

    iput-object p10, p0, Llyiahf/vczjk/cg6;->OooOo0O:Llyiahf/vczjk/mj4;

    iput p11, p0, Llyiahf/vczjk/cg6;->OooOo0o:I

    iput p12, p0, Llyiahf/vczjk/cg6;->OooOo:I

    iput-object p13, p0, Llyiahf/vczjk/cg6;->OooOoO0:Llyiahf/vczjk/ml9;

    iput-object p14, p0, Llyiahf/vczjk/cg6;->OooOoO:Llyiahf/vczjk/rr5;

    iput-object p15, p0, Llyiahf/vczjk/cg6;->OooOoOO:Llyiahf/vczjk/a91;

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/cg6;->OooOoo0:Llyiahf/vczjk/qj8;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eq v3, v5, :cond_0

    move v3, v6

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    and-int/2addr v2, v6

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_5

    iget-object v2, v0, Llyiahf/vczjk/cg6;->OooOOO:Llyiahf/vczjk/a91;

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v2, :cond_2

    const v2, -0x35da2c2d

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v5, :cond_1

    new-instance v2, Llyiahf/vczjk/ow;

    const/16 v5, 0x1a

    invoke-direct {v2, v5}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-static {v3, v6, v2}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-static {v1}, Llyiahf/vczjk/wi9;->OooO0o0(Llyiahf/vczjk/rf1;)F

    move-result v9

    const/4 v8, 0x0

    const/16 v12, 0xd

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_2
    const v2, -0x35d45166    # -2812838.5f

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1
    iget-object v2, v0, Llyiahf/vczjk/cg6;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v2, Landroidx/compose/ui/R$string;->default_error_message:I

    invoke-static {v2, v1}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    sget v5, Llyiahf/vczjk/wi9;->OooO00o:F

    iget-boolean v5, v0, Llyiahf/vczjk/cg6;->OooOOOO:Z

    if-eqz v5, :cond_3

    new-instance v6, Llyiahf/vczjk/kf0;

    const/16 v7, 0xd

    invoke-direct {v6, v2, v7}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    invoke-static {v3, v4, v6}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    :cond_3
    sget v2, Llyiahf/vczjk/xf6;->OooO0OO:F

    sget v4, Llyiahf/vczjk/xf6;->OooO0O0:F

    invoke-static {v3, v2, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v9

    new-instance v2, Llyiahf/vczjk/gx8;

    iget-object v3, v0, Llyiahf/vczjk/cg6;->OooOOOo:Llyiahf/vczjk/ei9;

    if-eqz v5, :cond_4

    iget-wide v4, v3, Llyiahf/vczjk/ei9;->OooOO0:J

    goto :goto_2

    :cond_4
    iget-wide v4, v3, Llyiahf/vczjk/ei9;->OooO:J

    :goto_2
    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v10, Llyiahf/vczjk/bg6;

    iget-object v4, v0, Llyiahf/vczjk/cg6;->OooOoo0:Llyiahf/vczjk/qj8;

    iget-object v7, v0, Llyiahf/vczjk/cg6;->OooOOo0:Ljava/lang/String;

    iget-boolean v12, v0, Llyiahf/vczjk/cg6;->OooOOoo:Z

    iget-object v13, v0, Llyiahf/vczjk/cg6;->OooOoO0:Llyiahf/vczjk/ml9;

    iget-object v14, v0, Llyiahf/vczjk/cg6;->OooOoO:Llyiahf/vczjk/rr5;

    iget-boolean v15, v0, Llyiahf/vczjk/cg6;->OooOOOO:Z

    iget-object v5, v0, Llyiahf/vczjk/cg6;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v6, v0, Llyiahf/vczjk/cg6;->OooOoOO:Llyiahf/vczjk/a91;

    move-object/from16 v18, v3

    move-object/from16 v19, v4

    move-object/from16 v16, v5

    move-object/from16 v17, v6

    move-object v11, v7

    invoke-direct/range {v10 .. v19}, Llyiahf/vczjk/bg6;-><init>(Ljava/lang/String;ZLlyiahf/vczjk/ml9;Llyiahf/vczjk/rr5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;)V

    const v3, -0x46e2e35b

    invoke-static {v3, v10, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    move v10, v12

    iget-object v12, v0, Llyiahf/vczjk/cg6;->OooOo00:Llyiahf/vczjk/rn9;

    const/high16 v25, 0x30000

    const/16 v26, 0x1000

    iget-object v8, v0, Llyiahf/vczjk/cg6;->OooOOo:Llyiahf/vczjk/oe3;

    const/4 v11, 0x0

    move-object/from16 v18, v13

    iget-object v13, v0, Llyiahf/vczjk/cg6;->OooOo0:Llyiahf/vczjk/nj4;

    move-object/from16 v20, v14

    iget-object v14, v0, Llyiahf/vczjk/cg6;->OooOo0O:Llyiahf/vczjk/mj4;

    const/4 v15, 0x0

    iget v3, v0, Llyiahf/vczjk/cg6;->OooOo0o:I

    iget v4, v0, Llyiahf/vczjk/cg6;->OooOo:I

    const/16 v19, 0x0

    const/16 v24, 0x0

    move-object/from16 v23, v1

    move-object/from16 v21, v2

    move/from16 v16, v3

    move/from16 v17, v4

    invoke-static/range {v7 .. v26}, Llyiahf/vczjk/w90;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;ZIILlyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;III)V

    goto :goto_3

    :cond_5
    move-object/from16 v23, v1

    invoke-virtual/range {v23 .. v23}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
