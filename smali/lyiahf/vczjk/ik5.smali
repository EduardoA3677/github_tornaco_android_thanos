.class public final Llyiahf/vczjk/ik5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:Llyiahf/vczjk/zl8;

.field public final synthetic OooOOOo:Llyiahf/vczjk/gi;

.field public final synthetic OooOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOoo:Llyiahf/vczjk/hl5;

.field public final synthetic OooOo:J

.field public final synthetic OooOo0:Z

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:Llyiahf/vczjk/qj8;

.field public final synthetic OooOo0o:J

.field public final synthetic OooOoO:Llyiahf/vczjk/a91;

.field public final synthetic OooOoO0:F

.field public final synthetic OooOoOO:Llyiahf/vczjk/md1;

.field public final synthetic OooOoo0:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/zl8;Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;FZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/a91;Llyiahf/vczjk/md1;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/ik5;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/ik5;->OooOOO:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/ik5;->OooOOOO:Llyiahf/vczjk/zl8;

    iput-object p5, p0, Llyiahf/vczjk/ik5;->OooOOOo:Llyiahf/vczjk/gi;

    iput-object p6, p0, Llyiahf/vczjk/ik5;->OooOOo0:Llyiahf/vczjk/xr1;

    iput-object p7, p0, Llyiahf/vczjk/ik5;->OooOOo:Llyiahf/vczjk/oe3;

    iput-object p8, p0, Llyiahf/vczjk/ik5;->OooOOoo:Llyiahf/vczjk/hl5;

    iput p9, p0, Llyiahf/vczjk/ik5;->OooOo00:F

    iput-boolean p10, p0, Llyiahf/vczjk/ik5;->OooOo0:Z

    iput-object p11, p0, Llyiahf/vczjk/ik5;->OooOo0O:Llyiahf/vczjk/qj8;

    iput-wide p12, p0, Llyiahf/vczjk/ik5;->OooOo0o:J

    iput-wide p14, p0, Llyiahf/vczjk/ik5;->OooOo:J

    move/from16 p1, p16

    iput p1, p0, Llyiahf/vczjk/ik5;->OooOoO0:F

    move-object/from16 p1, p17

    iput-object p1, p0, Llyiahf/vczjk/ik5;->OooOoO:Llyiahf/vczjk/a91;

    move-object/from16 p1, p18

    iput-object p1, p0, Llyiahf/vczjk/ik5;->OooOoOO:Llyiahf/vczjk/md1;

    move-object/from16 p1, p19

    iput-object p1, p0, Llyiahf/vczjk/ik5;->OooOoo0:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

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

    move-object v11, v1

    check-cast v11, Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_6

    sget-object v1, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    new-instance v2, Llyiahf/vczjk/pc;

    const/4 v3, 0x3

    const/4 v5, 0x7

    invoke-direct {v2, v3, v5}, Llyiahf/vczjk/pc;-><init>(II)V

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v3, :cond_1

    new-instance v2, Llyiahf/vczjk/rt3;

    const/4 v3, 0x6

    invoke-direct {v2, v3}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-static {v1, v4, v2}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v2, v4}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    iget v3, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v11, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_2

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_4

    :cond_3
    invoke-static {v3, v11, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v11, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v1, v0, Llyiahf/vczjk/ik5;->OooOOOO:Llyiahf/vczjk/zl8;

    iget-object v2, v1, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v2, v2, Llyiahf/vczjk/c9;->OooO0oo:Llyiahf/vczjk/w62;

    invoke-virtual {v2}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/am8;

    sget-object v3, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    if-eq v2, v3, :cond_5

    move v10, v6

    goto :goto_2

    :cond_5
    move v10, v4

    :goto_2
    iget-wide v7, v0, Llyiahf/vczjk/ik5;->OooOOO0:J

    iget-object v9, v0, Llyiahf/vczjk/ik5;->OooOOO:Llyiahf/vczjk/le3;

    const/4 v12, 0x0

    invoke-static/range {v7 .. v12}, Llyiahf/vczjk/uk5;->OooO0OO(JLlyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V

    move-object/from16 v24, v11

    iget-object v2, v0, Llyiahf/vczjk/ik5;->OooOoo0:Llyiahf/vczjk/a91;

    iget-object v3, v0, Llyiahf/vczjk/ik5;->OooOoO:Llyiahf/vczjk/a91;

    iget-object v4, v0, Llyiahf/vczjk/ik5;->OooOoOO:Llyiahf/vczjk/md1;

    iget-object v7, v0, Llyiahf/vczjk/ik5;->OooOOOo:Llyiahf/vczjk/gi;

    iget-object v8, v0, Llyiahf/vczjk/ik5;->OooOOo0:Llyiahf/vczjk/xr1;

    iget-object v10, v0, Llyiahf/vczjk/ik5;->OooOOo:Llyiahf/vczjk/oe3;

    iget-object v11, v0, Llyiahf/vczjk/ik5;->OooOOoo:Llyiahf/vczjk/hl5;

    iget v13, v0, Llyiahf/vczjk/ik5;->OooOo00:F

    iget-boolean v14, v0, Llyiahf/vczjk/ik5;->OooOo0:Z

    iget-object v15, v0, Llyiahf/vczjk/ik5;->OooOo0O:Llyiahf/vczjk/qj8;

    move-object v5, v7

    iget-wide v6, v0, Llyiahf/vczjk/ik5;->OooOo0o:J

    move-object v12, v1

    move-object/from16 v23, v2

    iget-wide v1, v0, Llyiahf/vczjk/ik5;->OooOo:J

    move-wide/from16 v18, v1

    iget v1, v0, Llyiahf/vczjk/ik5;->OooOoO0:F

    const/16 v25, 0x46

    move/from16 v20, v1

    move-object/from16 v21, v3

    move-object/from16 v22, v4

    move-wide/from16 v16, v6

    move-object v7, v5

    invoke-static/range {v7 .. v25}, Llyiahf/vczjk/uk5;->OooO0O0(Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/zl8;FZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    move-object/from16 v11, v24

    const/4 v1, 0x1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_6
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
