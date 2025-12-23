.class public final Llyiahf/vczjk/s57;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;ZII)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/s57;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/s57;->OooOOO:Llyiahf/vczjk/oe3;

    iput-boolean p2, p0, Llyiahf/vczjk/s57;->OooOOOO:Z

    iput p3, p0, Llyiahf/vczjk/s57;->OooOOOo:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/s57;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/4 v5, 0x0

    const/4 v6, 0x1

    invoke-static {v5, v1, v6}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide v7

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v4, v7, v8, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v4

    check-cast v1, Llyiahf/vczjk/zf1;

    const v5, -0x615d173a

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/s57;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    iget-boolean v8, v0, Llyiahf/vczjk/s57;->OooOOOO:Z

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    or-int/2addr v7, v9

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_2

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v7, :cond_3

    :cond_2
    new-instance v9, Llyiahf/vczjk/ev0;

    const/4 v7, 0x6

    invoke-direct {v9, v5, v8, v7}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v9, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v9}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v7, 0x14

    int-to-float v7, v7

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v4, v7, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v1, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_4

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_6

    :cond_5
    invoke-static {v9, v1, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v13, 0x36

    invoke-static {v3, v4, v1, v13}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_7

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    invoke-static {v3, v1, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v13, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v3, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_9

    :cond_8
    invoke-static {v4, v1, v4, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    invoke-static {v2, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Running - "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v3, v0, Llyiahf/vczjk/s57;->OooOOOo:I

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v28, 0x0

    const v29, 0x1fffe

    move v3, v8

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v27, 0x0

    move-object/from16 v26, v1

    move-object/from16 v25, v2

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v3, v1, v5}, Llyiahf/vczjk/vt6;->OooO0OO(ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_b

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_a

    goto :goto_4

    :cond_a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_b
    :goto_4
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/4 v5, 0x0

    const/4 v6, 0x1

    invoke-static {v5, v1, v6}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide v7

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v4, v7, v8, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v4

    check-cast v1, Llyiahf/vczjk/zf1;

    const v5, -0x615d173a

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/s57;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    iget-boolean v8, v0, Llyiahf/vczjk/s57;->OooOOOO:Z

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v9

    or-int/2addr v7, v9

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_c

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v7, :cond_d

    :cond_c
    new-instance v9, Llyiahf/vczjk/ev0;

    const/4 v7, 0x5

    invoke-direct {v9, v5, v8, v7}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v9, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v9}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v7, 0x14

    int-to-float v7, v7

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v4, v7, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v1, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_e

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_e
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_f

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_10

    :cond_f
    invoke-static {v9, v1, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v13, 0x36

    invoke-static {v3, v4, v1, v13}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_11

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_11
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v3, v1, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v13, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_12

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v3, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_13

    :cond_12
    invoke-static {v4, v1, v4, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_13
    invoke-static {v2, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Bg - "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v3, v0, Llyiahf/vczjk/s57;->OooOOOo:I

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v28, 0x0

    const v29, 0x1fffe

    move v3, v8

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v27, 0x0

    move-object/from16 v26, v1

    move-object/from16 v25, v2

    invoke-static/range {v7 .. v29}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v3, v1, v5}, Llyiahf/vczjk/vt6;->OooO0OO(ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_7
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
