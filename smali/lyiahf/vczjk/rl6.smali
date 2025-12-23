.class public abstract Llyiahf/vczjk/rl6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static OooO0O0:Z


# direct methods
.method public static OooO(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    const-string v0, "value"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " value: "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move-object/from16 v0, p0

    move/from16 v1, p2

    move-object/from16 v9, p1

    check-cast v9, Llyiahf/vczjk/zf1;

    const v2, -0x23bface1

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit16 v2, v1, 0x1b0

    and-int/lit16 v2, v2, 0x93

    const/16 v3, 0x92

    if-ne v2, v3, :cond_1

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2

    :cond_1
    :goto_0
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v4, 0x36

    invoke-static {v2, v3, v9, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    iget v3, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v9, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_2

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v9, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_3

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_4

    :cond_3
    invoke-static {v3, v9, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v2, 0x20

    int-to-float v11, v2

    const/4 v12, 0x0

    const/4 v14, 0x0

    const/16 v15, 0xa

    move v13, v11

    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/16 v3, -0x50

    int-to-float v3, v3

    const/4 v4, 0x0

    const/4 v12, 0x1

    invoke-static {v2, v4, v3, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$drawable;->ui_load_error:I

    invoke-static {v2, v9}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v2

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/16 v10, 0x1b0

    const/16 v11, 0x78

    invoke-static/range {v2 .. v11}, Llyiahf/vczjk/c6a;->OooOOO(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;FLlyiahf/vczjk/p21;Llyiahf/vczjk/rf1;II)V

    const v2, 0x61ba05e3

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v2, 0x0

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, 0x61ba2f81

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_5

    new-instance v3, Llyiahf/vczjk/f16;

    const/4 v4, 0x2

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/f16;-><init>(Llyiahf/vczjk/kl5;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x43322f6c

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 p1, p2, 0x3

    const/4 v0, 0x2

    if-ne p1, v0, :cond_1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v0, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/16 v1, 0x36

    invoke-static {v0, p1, v8, v1}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object p1

    iget v0, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v1

    invoke-static {v8, p0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v4, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_2

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {p1, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, p1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v1, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    :cond_3
    invoke-static {v0, v8, v0, p1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object p1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, p1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v0, 0x30

    int-to-float v0, v0

    invoke-static {p1, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/4 p1, 0x6

    int-to-float v3, p1

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-wide/16 v1, 0x0

    const-wide/16 v4, 0x0

    const/16 v9, 0x186

    const/16 v10, 0x3a

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/ea7;->OooO00o(Llyiahf/vczjk/kl5;JFJIFLlyiahf/vczjk/rf1;II)V

    const/4 p1, 0x1

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_2
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/f16;

    const/4 v1, 0x1

    invoke-direct {v0, p0, p2, v1}, Llyiahf/vczjk/f16;-><init>(Llyiahf/vczjk/kl5;II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/ro4;Z)Llyiahf/vczjk/re8;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jl5;

    iget v1, v0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v1, v1, 0x8

    const/4 v2, 0x0

    if-eqz v1, :cond_8

    :goto_0
    if-eqz v0, :cond_8

    iget v1, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, v1, 0x8

    if-eqz v1, :cond_7

    move-object v1, v0

    move-object v3, v2

    :goto_1
    if-eqz v1, :cond_7

    instance-of v4, v1, Llyiahf/vczjk/ne8;

    if-eqz v4, :cond_0

    move-object v2, v1

    goto :goto_4

    :cond_0
    iget v4, v1, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v4, v4, 0x8

    if-eqz v4, :cond_6

    instance-of v4, v1, Llyiahf/vczjk/m52;

    if-eqz v4, :cond_6

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/m52;

    iget-object v4, v4, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v5, 0x0

    :goto_2
    const/4 v6, 0x1

    if-eqz v4, :cond_5

    iget v7, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v7, v7, 0x8

    if-eqz v7, :cond_4

    add-int/lit8 v5, v5, 0x1

    if-ne v5, v6, :cond_1

    move-object v1, v4

    goto :goto_3

    :cond_1
    if-nez v3, :cond_2

    new-instance v3, Llyiahf/vczjk/ws5;

    const/16 v6, 0x10

    new-array v6, v6, [Llyiahf/vczjk/jl5;

    invoke-direct {v3, v6}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_2
    if-eqz v1, :cond_3

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v1, v2

    :cond_3
    invoke-virtual {v3, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_4
    :goto_3
    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_5
    if-ne v5, v6, :cond_6

    goto :goto_1

    :cond_6
    invoke-static {v3}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v1

    goto :goto_1

    :cond_7
    iget v1, v0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v1, v1, 0x8

    if-eqz v1, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_8
    :goto_4
    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v2, Llyiahf/vczjk/ne8;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget-object v0, v2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v1

    if-nez v1, :cond_9

    new-instance v1, Llyiahf/vczjk/je8;

    invoke-direct {v1}, Llyiahf/vczjk/je8;-><init>()V

    :cond_9
    new-instance v2, Llyiahf/vczjk/re8;

    invoke-direct {v2, v0, p1, p0, v1}, Llyiahf/vczjk/re8;-><init>(Llyiahf/vczjk/jl5;ZLlyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V

    return-object v2
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V
    .locals 8

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x7d7b3e30

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p4, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v1, p3, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v1, p3, 0x6

    if-nez v1, :cond_2

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 v1, 0x4

    goto :goto_0

    :cond_1
    const/4 v1, 0x2

    :goto_0
    or-int/2addr v1, p3

    goto :goto_1

    :cond_2
    move v1, p3

    :goto_1
    and-int/lit8 v2, p4, 0x2

    if-eqz v2, :cond_3

    or-int/lit8 v1, v1, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v2, p3, 0x30

    if-nez v2, :cond_5

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    const/16 v2, 0x20

    goto :goto_2

    :cond_4
    const/16 v2, 0x10

    :goto_2
    or-int/2addr v1, v2

    :cond_5
    :goto_3
    and-int/lit8 v2, v1, 0x13

    const/16 v3, 0x12

    const/4 v4, 0x1

    if-eq v2, v3, :cond_6

    move v2, v4

    goto :goto_4

    :cond_6
    const/4 v2, 0x0

    :goto_4
    and-int/lit8 v3, v1, 0x1

    invoke-virtual {p2, v3, v2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_b

    if-eqz v0, :cond_7

    sget-object p0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :cond_7
    sget-object v0, Llyiahf/vczjk/wc;->OooOO0:Llyiahf/vczjk/wc;

    shr-int/lit8 v2, v1, 0x3

    and-int/lit8 v2, v2, 0xe

    or-int/lit16 v2, v2, 0x180

    shl-int/lit8 v1, v1, 0x3

    and-int/lit8 v1, v1, 0x70

    or-int/2addr v1, v2

    iget v2, p2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p2, p0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    shl-int/lit8 v1, v1, 0x6

    and-int/lit16 v1, v1, 0x380

    or-int/lit8 v1, v1, 0x6

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_8

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p2, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, p2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_9

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_a

    :cond_9
    invoke-static {v2, p2, v2, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, p2, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    shr-int/lit8 v0, v1, 0x6

    and-int/lit8 v0, v0, 0xe

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_b
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_c

    new-instance v0, Llyiahf/vczjk/po8;

    invoke-direct {v0, p0, p1, p3, p4}, Llyiahf/vczjk/po8;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ze3;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static final OooO0o(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/ky4;)Llyiahf/vczjk/fga;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v0

    if-lez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/o0OO00o0;

    const/4 v1, 0x4

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/o0OO00o0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    new-instance p0, Llyiahf/vczjk/fga;

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/fga;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/o0OO00o0;)V

    return-object p0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot configure "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " to disposeComposition at Lifecycle ON_DESTROY: "

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, "is already destroyed"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public static final OooO0o0([F)I
    .locals 6

    array-length v0, p0

    const/16 v1, 0x10

    const/4 v2, 0x0

    if-ge v0, v1, :cond_0

    return v2

    :cond_0
    aget v0, p0, v2

    const/high16 v1, 0x3f800000    # 1.0f

    cmpg-float v0, v0, v1

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-nez v0, :cond_1

    aget v0, p0, v3

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/4 v0, 0x2

    aget v0, p0, v0

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/4 v0, 0x4

    aget v0, p0, v0

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/4 v0, 0x5

    aget v0, p0, v0

    cmpg-float v0, v0, v1

    if-nez v0, :cond_1

    const/4 v0, 0x6

    aget v0, p0, v0

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/16 v0, 0x8

    aget v0, p0, v0

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/16 v0, 0x9

    aget v0, p0, v0

    cmpg-float v0, v0, v4

    if-nez v0, :cond_1

    const/16 v0, 0xa

    aget v0, p0, v0

    cmpg-float v0, v0, v1

    if-nez v0, :cond_1

    move v0, v3

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    const/16 v5, 0xc

    aget v5, p0, v5

    cmpg-float v5, v5, v4

    if-nez v5, :cond_2

    const/16 v5, 0xd

    aget v5, p0, v5

    cmpg-float v5, v5, v4

    if-nez v5, :cond_2

    const/16 v5, 0xe

    aget v5, p0, v5

    cmpg-float v4, v5, v4

    if-nez v4, :cond_2

    const/16 v4, 0xf

    aget p0, p0, v4

    cmpg-float p0, p0, v1

    if-nez p0, :cond_2

    move v2, v3

    :cond_2
    shl-int/lit8 p0, v0, 0x1

    or-int/2addr p0, v2

    return p0
.end method

.method public static final OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;
    .locals 1

    const-string v0, "exception"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/ts7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ts7;-><init>(Ljava/lang/Throwable;)V

    return-object v0
.end method

.method public static final OooOO0(Llyiahf/vczjk/lm6;)J
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v0

    int-to-long v0, v0

    invoke-virtual {p0}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result v2

    int-to-long v2, v2

    mul-long/2addr v0, v2

    iget-object v2, p0, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {v2}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    move-result v2

    invoke-virtual {p0}, Llyiahf/vczjk/lm6;->OooOOO()I

    move-result p0

    int-to-float p0, p0

    mul-float/2addr v2, p0

    float-to-double v2, v2

    invoke-static {v2, v3}, Llyiahf/vczjk/ye5;->Oooo00o(D)J

    move-result-wide v2

    add-long/2addr v2, v0

    return-wide v2
.end method

.method public static final OooOO0O(FJ)J
    .locals 1

    invoke-static {p1, p2}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    div-float/2addr v0, p0

    invoke-static {p1, p2}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p1

    div-float/2addr p1, p0

    invoke-static {v0, p1}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOO0o(JJ)F
    .locals 2

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v1

    mul-float/2addr v1, v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p1

    mul-float/2addr p1, p0

    add-float/2addr p1, v1

    return p1
.end method

.method public static final OooOOO(II[F)F
    .locals 0

    sub-int/2addr p0, p1

    mul-int/lit8 p0, p0, 0x2

    add-int/lit8 p0, p0, 0x1

    aget p0, p2, p0

    return p0
.end method

.method public static final OooOOO0(Llyiahf/vczjk/gz6;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/by9;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/by9;-><init>(I)V

    invoke-interface {p0, p1, v0, p2}, Llyiahf/vczjk/gz6;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final OooOOOO(J)J
    .locals 3

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v1

    mul-float/2addr v1, v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    mul-float/2addr v2, v0

    add-float/2addr v2, v1

    float-to-double v0, v2

    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v0

    double-to-float v0, v0

    const/4 v1, 0x0

    cmpl-float v1, v0, v1

    if-lez v1, :cond_0

    invoke-static {v0, p0, p1}, Llyiahf/vczjk/rl6;->OooOO0O(FJ)J

    move-result-wide p0

    return-wide p0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Can\'t get the direction of a 0-length vector"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOOOo(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/ne8;
    .locals 7

    iget-object p0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object p0, p0, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/jl5;

    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v0, v0, 0x8

    const/4 v1, 0x0

    if-eqz v0, :cond_8

    :goto_0
    if-eqz p0, :cond_8

    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_7

    move-object v0, p0

    move-object v2, v1

    :goto_1
    if-eqz v0, :cond_7

    instance-of v3, v0, Llyiahf/vczjk/ne8;

    if-eqz v3, :cond_0

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/ne8;

    invoke-interface {v3}, Llyiahf/vczjk/ne8;->o0ooOoO()Z

    move-result v3

    if-eqz v3, :cond_6

    move-object v1, v0

    goto :goto_4

    :cond_0
    iget v3, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v3, v3, 0x8

    if-eqz v3, :cond_6

    instance-of v3, v0, Llyiahf/vczjk/m52;

    if-eqz v3, :cond_6

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/m52;

    iget-object v3, v3, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v4, 0x0

    :goto_2
    const/4 v5, 0x1

    if-eqz v3, :cond_5

    iget v6, v3, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v6, v6, 0x8

    if-eqz v6, :cond_4

    add-int/lit8 v4, v4, 0x1

    if-ne v4, v5, :cond_1

    move-object v0, v3

    goto :goto_3

    :cond_1
    if-nez v2, :cond_2

    new-instance v2, Llyiahf/vczjk/ws5;

    const/16 v5, 0x10

    new-array v5, v5, [Llyiahf/vczjk/jl5;

    invoke-direct {v2, v5}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_2
    if-eqz v0, :cond_3

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v0, v1

    :cond_3
    invoke-virtual {v2, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_4
    :goto_3
    iget-object v3, v3, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_5
    if-ne v4, v5, :cond_6

    goto :goto_1

    :cond_6
    invoke-static {v2}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v0

    goto :goto_1

    :cond_7
    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_8

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_8
    :goto_4
    check-cast v1, Llyiahf/vczjk/ne8;

    return-object v1
.end method

.method public static final OooOOo(J)F
    .locals 1

    const/16 v0, 0x20

    shr-long/2addr p0, v0

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    return p0
.end method

.method public static final OooOOo0(Llyiahf/vczjk/km9;Landroid/text/Layout;Llyiahf/vczjk/mi;ILandroid/graphics/RectF;Llyiahf/vczjk/ad8;Llyiahf/vczjk/ke;Z)I
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p3

    move-object/from16 v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineTop(I)I

    move-result v7

    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineBottom(I)I

    move-result v8

    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineStart(I)I

    move-result v9

    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineEnd(I)I

    move-result v1

    if-ne v9, v1, :cond_1

    :cond_0
    const/4 v12, -0x1

    goto/16 :goto_1e

    :cond_1
    sub-int/2addr v1, v9

    mul-int/lit8 v1, v1, 0x2

    new-array v11, v1, [F

    iget-object v12, v0, Llyiahf/vczjk/km9;->OooO0o:Landroid/text/Layout;

    invoke-virtual {v12, v3}, Landroid/text/Layout;->getLineStart(I)I

    move-result v13

    invoke-virtual {v0, v3}, Llyiahf/vczjk/km9;->OooO0o(I)I

    move-result v14

    sub-int v15, v14, v13

    mul-int/lit8 v15, v15, 0x2

    if-lt v1, v15, :cond_2

    goto :goto_0

    :cond_2
    const-string v1, "array.size - arrayStart must be greater or equal than (endOffset - startOffset) * 2"

    invoke-static {v1}, Llyiahf/vczjk/qz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    new-instance v1, Llyiahf/vczjk/mo3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/mo3;-><init>(Llyiahf/vczjk/km9;)V

    invoke-virtual {v12, v3}, Landroid/text/Layout;->getParagraphDirection(I)I

    move-result v0

    const/4 v15, 0x1

    const/4 v10, 0x0

    if-ne v0, v15, :cond_3

    move v0, v15

    goto :goto_1

    :cond_3
    move v0, v10

    :goto_1
    move/from16 v16, v10

    :goto_2
    if-ge v13, v14, :cond_7

    invoke-virtual {v12, v13}, Landroid/text/Layout;->isRtlCharAt(I)Z

    move-result v17

    if-eqz v0, :cond_4

    if-nez v17, :cond_4

    invoke-virtual {v1, v13, v10, v10, v15}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v17

    add-int/lit8 v10, v13, 0x1

    invoke-virtual {v1, v10, v15, v15, v15}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v10

    move/from16 v18, v0

    goto :goto_4

    :cond_4
    if-eqz v0, :cond_5

    if-eqz v17, :cond_5

    const/4 v10, 0x0

    invoke-virtual {v1, v13, v10, v10, v10}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v17

    move/from16 v18, v0

    add-int/lit8 v0, v13, 0x1

    invoke-virtual {v1, v0, v15, v15, v10}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v0

    move/from16 v10, v17

    move/from16 v17, v0

    goto :goto_4

    :cond_5
    move/from16 v18, v0

    const/4 v10, 0x0

    if-eqz v17, :cond_6

    invoke-virtual {v1, v13, v10, v10, v15}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v0

    add-int/lit8 v10, v13, 0x1

    invoke-virtual {v1, v10, v15, v15, v15}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v17

    :goto_3
    move v10, v0

    goto :goto_4

    :cond_6
    invoke-virtual {v1, v13, v10, v10, v10}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v17

    add-int/lit8 v0, v13, 0x1

    invoke-virtual {v1, v0, v15, v15, v10}, Llyiahf/vczjk/mo3;->OooO00o(IZZZ)F

    move-result v0

    goto :goto_3

    :goto_4
    aput v17, v11, v16

    add-int/lit8 v0, v16, 0x1

    aput v10, v11, v0

    add-int/lit8 v16, v16, 0x2

    add-int/lit8 v13, v13, 0x1

    move/from16 v0, v18

    const/4 v10, 0x0

    goto :goto_2

    :cond_7
    iget-object v0, v2, Llyiahf/vczjk/mi;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Landroid/text/Layout;

    invoke-virtual {v0, v3}, Landroid/text/Layout;->getLineStart(I)I

    move-result v1

    invoke-virtual {v0, v3}, Landroid/text/Layout;->getLineEnd(I)I

    move-result v3

    const/4 v10, 0x0

    invoke-virtual {v2, v1, v10}, Llyiahf/vczjk/mi;->OooOOoo(IZ)I

    move-result v12

    invoke-virtual {v2, v12}, Llyiahf/vczjk/mi;->OooOo0O(I)I

    move-result v10

    sub-int v13, v1, v10

    sub-int v10, v3, v10

    invoke-virtual {v2, v12}, Llyiahf/vczjk/mi;->OooO0OO(I)Ljava/text/Bidi;

    move-result-object v2

    if-eqz v2, :cond_a

    invoke-virtual {v2, v13, v10}, Ljava/text/Bidi;->createLineBidi(II)Ljava/text/Bidi;

    move-result-object v2

    if-nez v2, :cond_8

    goto :goto_7

    :cond_8
    invoke-virtual {v2}, Ljava/text/Bidi;->getRunCount()I

    move-result v0

    new-array v3, v0, [Llyiahf/vczjk/zn4;

    const/4 v10, 0x0

    :goto_5
    if-ge v10, v0, :cond_b

    new-instance v12, Llyiahf/vczjk/zn4;

    invoke-virtual {v2, v10}, Ljava/text/Bidi;->getRunStart(I)I

    move-result v13

    add-int/2addr v13, v1

    invoke-virtual {v2, v10}, Ljava/text/Bidi;->getRunLimit(I)I

    move-result v14

    add-int/2addr v14, v1

    invoke-virtual {v2, v10}, Ljava/text/Bidi;->getRunLevel(I)I

    move-result v16

    move/from16 p2, v0

    rem-int/lit8 v0, v16, 0x2

    if-ne v0, v15, :cond_9

    move v0, v15

    goto :goto_6

    :cond_9
    const/4 v0, 0x0

    :goto_6
    invoke-direct {v12, v13, v14, v0}, Llyiahf/vczjk/zn4;-><init>(IIZ)V

    aput-object v12, v3, v10

    add-int/lit8 v10, v10, 0x1

    move/from16 v0, p2

    goto :goto_5

    :cond_a
    :goto_7
    new-instance v2, Llyiahf/vczjk/zn4;

    invoke-virtual {v0, v1}, Landroid/text/Layout;->isRtlCharAt(I)Z

    move-result v0

    invoke-direct {v2, v1, v3, v0}, Llyiahf/vczjk/zn4;-><init>(IIZ)V

    filled-new-array {v2}, [Llyiahf/vczjk/zn4;

    move-result-object v3

    :cond_b
    if-eqz p7, :cond_c

    new-instance v0, Llyiahf/vczjk/x14;

    array-length v1, v3

    sub-int/2addr v1, v15

    const/4 v10, 0x0

    invoke-direct {v0, v10, v1, v15}, Llyiahf/vczjk/v14;-><init>(III)V

    goto :goto_8

    :cond_c
    const/4 v10, 0x0

    array-length v0, v3

    sub-int/2addr v0, v15

    new-instance v1, Llyiahf/vczjk/v14;

    const/4 v2, -0x1

    invoke-direct {v1, v0, v10, v2}, Llyiahf/vczjk/v14;-><init>(III)V

    move-object v0, v1

    :goto_8
    iget v1, v0, Llyiahf/vczjk/v14;->OooOOO0:I

    iget v2, v0, Llyiahf/vczjk/v14;->OooOOO:I

    iget v0, v0, Llyiahf/vczjk/v14;->OooOOOO:I

    if-lez v0, :cond_d

    if-le v1, v2, :cond_e

    :cond_d
    if-gez v0, :cond_0

    if-gt v2, v1, :cond_0

    :cond_e
    :goto_9
    aget-object v10, v3, v1

    iget-boolean v12, v10, Llyiahf/vczjk/zn4;->OooO0OO:Z

    iget v13, v10, Llyiahf/vczjk/zn4;->OooO00o:I

    iget v14, v10, Llyiahf/vczjk/zn4;->OooO0O0:I

    if-eqz v12, :cond_f

    add-int/lit8 v16, v14, -0x1

    sub-int v16, v16, v9

    mul-int/lit8 v16, v16, 0x2

    aget v16, v11, v16

    goto :goto_a

    :cond_f
    sub-int v16, v13, v9

    mul-int/lit8 v16, v16, 0x2

    aget v16, v11, v16

    :goto_a
    if-eqz v12, :cond_10

    invoke-static {v13, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v12

    goto :goto_b

    :cond_10
    add-int/lit8 v12, v14, -0x1

    invoke-static {v12, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v12

    :goto_b
    iget-boolean v10, v10, Llyiahf/vczjk/zn4;->OooO0OO:Z

    if-eqz p7, :cond_25

    iget v15, v4, Landroid/graphics/RectF;->left:F

    cmpl-float v17, v12, v15

    if-ltz v17, :cond_24

    move/from16 v17, v0

    iget v0, v4, Landroid/graphics/RectF;->right:F

    cmpg-float v18, v16, v0

    if-gtz v18, :cond_19

    if-nez v10, :cond_11

    cmpg-float v15, v15, v16

    if-lez v15, :cond_12

    :cond_11
    if-eqz v10, :cond_13

    cmpl-float v0, v0, v12

    if-ltz v0, :cond_13

    :cond_12
    move v0, v13

    goto :goto_d

    :cond_13
    move v12, v13

    move v0, v14

    :goto_c
    sub-int v15, v0, v12

    move/from16 p3, v0

    const/4 v0, 0x1

    if-le v15, v0, :cond_17

    add-int v0, p3, v12

    div-int/lit8 v0, v0, 0x2

    sub-int v15, v0, v9

    mul-int/lit8 v15, v15, 0x2

    aget v15, v11, v15

    move/from16 v16, v0

    if-nez v10, :cond_14

    iget v0, v4, Landroid/graphics/RectF;->left:F

    cmpl-float v0, v15, v0

    if-gtz v0, :cond_15

    :cond_14
    if-eqz v10, :cond_16

    iget v0, v4, Landroid/graphics/RectF;->right:F

    cmpg-float v0, v15, v0

    if-gez v0, :cond_16

    :cond_15
    move/from16 v0, v16

    goto :goto_c

    :cond_16
    move/from16 v0, p3

    move/from16 v12, v16

    goto :goto_c

    :cond_17
    if-eqz v10, :cond_18

    move/from16 v0, p3

    goto :goto_d

    :cond_18
    move v0, v12

    :goto_d
    invoke-interface {v5, v0}, Llyiahf/vczjk/ad8;->OooO0oo(I)I

    move-result v0

    const/4 v12, -0x1

    if-ne v0, v12, :cond_1b

    :cond_19
    :goto_e
    move-object/from16 v18, v3

    :cond_1a
    :goto_f
    const/4 v13, -0x1

    goto/16 :goto_1d

    :cond_1b
    invoke-interface {v5, v0}, Llyiahf/vczjk/ad8;->OooO0oO(I)I

    move-result v12

    if-lt v12, v14, :cond_1c

    goto :goto_e

    :cond_1c
    if-ge v12, v13, :cond_1d

    goto :goto_10

    :cond_1d
    move v13, v12

    :goto_10
    if-le v0, v14, :cond_1e

    move v0, v14

    :cond_1e
    new-instance v12, Landroid/graphics/RectF;

    int-to-float v15, v7

    move/from16 p3, v0

    int-to-float v0, v8

    move-object/from16 v18, v3

    const/4 v3, 0x0

    invoke-direct {v12, v3, v15, v3, v0}, Landroid/graphics/RectF;-><init>(FFFF)V

    move/from16 v0, p3

    :cond_1f
    :goto_11
    if-eqz v10, :cond_20

    add-int/lit8 v3, v0, -0x1

    sub-int/2addr v3, v9

    mul-int/lit8 v3, v3, 0x2

    aget v3, v11, v3

    goto :goto_12

    :cond_20
    sub-int v3, v13, v9

    mul-int/lit8 v3, v3, 0x2

    aget v3, v11, v3

    :goto_12
    iput v3, v12, Landroid/graphics/RectF;->left:F

    if-eqz v10, :cond_21

    invoke-static {v13, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v0

    goto :goto_13

    :cond_21
    add-int/lit8 v0, v0, -0x1

    invoke-static {v0, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v0

    :goto_13
    iput v0, v12, Landroid/graphics/RectF;->right:F

    invoke-virtual {v6, v12, v4}, Llyiahf/vczjk/ke;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_22

    goto/16 :goto_1d

    :cond_22
    invoke-interface {v5, v13}, Llyiahf/vczjk/ad8;->OooO0Oo(I)I

    move-result v13

    const/4 v0, -0x1

    if-eq v13, v0, :cond_1a

    if-lt v13, v14, :cond_23

    goto :goto_f

    :cond_23
    invoke-interface {v5, v13}, Llyiahf/vczjk/ad8;->OooO0oo(I)I

    move-result v0

    if-le v0, v14, :cond_1f

    move v0, v14

    goto :goto_11

    :cond_24
    move/from16 v17, v0

    goto :goto_e

    :cond_25
    move/from16 v17, v0

    move-object/from16 v18, v3

    iget v0, v4, Landroid/graphics/RectF;->left:F

    cmpl-float v3, v12, v0

    if-ltz v3, :cond_2e

    iget v3, v4, Landroid/graphics/RectF;->right:F

    cmpg-float v15, v16, v3

    if-gtz v15, :cond_2e

    if-nez v10, :cond_26

    cmpl-float v3, v3, v12

    if-gez v3, :cond_27

    :cond_26
    if-eqz v10, :cond_28

    cmpg-float v0, v0, v16

    if-gtz v0, :cond_28

    :cond_27
    add-int/lit8 v0, v14, -0x1

    :goto_14
    const/4 v15, 0x1

    goto :goto_16

    :cond_28
    move v3, v13

    move v0, v14

    :goto_15
    sub-int v12, v0, v3

    const/4 v15, 0x1

    if-le v12, v15, :cond_2c

    add-int v12, v0, v3

    div-int/lit8 v12, v12, 0x2

    sub-int v15, v12, v9

    mul-int/lit8 v15, v15, 0x2

    aget v15, v11, v15

    move/from16 p3, v0

    if-nez v10, :cond_29

    iget v0, v4, Landroid/graphics/RectF;->right:F

    cmpl-float v0, v15, v0

    if-gtz v0, :cond_2a

    :cond_29
    if-eqz v10, :cond_2b

    iget v0, v4, Landroid/graphics/RectF;->left:F

    cmpg-float v0, v15, v0

    if-gez v0, :cond_2b

    :cond_2a
    move v0, v12

    goto :goto_15

    :cond_2b
    move/from16 v0, p3

    move v3, v12

    goto :goto_15

    :cond_2c
    move/from16 p3, v0

    if-eqz v10, :cond_2d

    move/from16 v0, p3

    goto :goto_14

    :cond_2d
    move v0, v3

    goto :goto_14

    :goto_16
    add-int/2addr v0, v15

    invoke-interface {v5, v0}, Llyiahf/vczjk/ad8;->OooO0oO(I)I

    move-result v0

    const/4 v12, -0x1

    if-ne v0, v12, :cond_2f

    :cond_2e
    :goto_17
    const/4 v14, -0x1

    goto :goto_1c

    :cond_2f
    invoke-interface {v5, v0}, Llyiahf/vczjk/ad8;->OooO0oo(I)I

    move-result v3

    if-gt v3, v13, :cond_30

    goto :goto_17

    :cond_30
    if-ge v0, v13, :cond_31

    move v0, v13

    :cond_31
    if-le v3, v14, :cond_32

    goto :goto_18

    :cond_32
    move v14, v3

    :goto_18
    new-instance v3, Landroid/graphics/RectF;

    int-to-float v12, v7

    int-to-float v15, v8

    move/from16 p3, v0

    const/4 v0, 0x0

    invoke-direct {v3, v0, v12, v0, v15}, Landroid/graphics/RectF;-><init>(FFFF)V

    move/from16 v0, p3

    :cond_33
    :goto_19
    if-eqz v10, :cond_34

    add-int/lit8 v12, v14, -0x1

    sub-int/2addr v12, v9

    mul-int/lit8 v12, v12, 0x2

    aget v12, v11, v12

    goto :goto_1a

    :cond_34
    sub-int v12, v0, v9

    mul-int/lit8 v12, v12, 0x2

    aget v12, v11, v12

    :goto_1a
    iput v12, v3, Landroid/graphics/RectF;->left:F

    if-eqz v10, :cond_35

    invoke-static {v0, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v0

    goto :goto_1b

    :cond_35
    add-int/lit8 v0, v14, -0x1

    invoke-static {v0, v9, v11}, Llyiahf/vczjk/rl6;->OooOOO(II[F)F

    move-result v0

    :goto_1b
    iput v0, v3, Landroid/graphics/RectF;->right:F

    invoke-virtual {v6, v3, v4}, Llyiahf/vczjk/ke;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_36

    goto :goto_1c

    :cond_36
    invoke-interface {v5, v14}, Llyiahf/vczjk/ad8;->OooO0o(I)I

    move-result v14

    const/4 v12, -0x1

    if-eq v14, v12, :cond_2e

    if-gt v14, v13, :cond_37

    goto :goto_17

    :cond_37
    invoke-interface {v5, v14}, Llyiahf/vczjk/ad8;->OooO0oO(I)I

    move-result v0

    if-ge v0, v13, :cond_33

    move v0, v13

    goto :goto_19

    :goto_1c
    move v13, v14

    :goto_1d
    if-ltz v13, :cond_38

    return v13

    :cond_38
    if-eq v1, v2, :cond_0

    add-int v1, v1, v17

    move/from16 v0, v17

    move-object/from16 v3, v18

    const/4 v15, 0x1

    goto/16 :goto_9

    :goto_1e
    return v12
.end method

.method public static final OooOOoo(J)F
    .locals 2

    const-wide v0, 0xffffffffL

    and-long/2addr p0, v0

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    return p0
.end method

.method public static final OooOo0(JJ)J
    .locals 2

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v1

    sub-float/2addr v0, v1

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p1

    sub-float/2addr p0, p1

    invoke-static {v0, p0}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOo0O(JJ)J
    .locals 2

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v1

    add-float/2addr v1, v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p0

    invoke-static {p2, p3}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p1

    add-float/2addr p1, p0

    invoke-static {v1, p1}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOo0o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;
    .locals 2

    sget-object v0, Llyiahf/vczjk/x77;->OooOOOo:Llyiahf/vczjk/x77;

    const/4 v1, 0x1

    invoke-static {p0, v1, v0}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOoo(FJ)J
    .locals 1

    invoke-static {p1, p2}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    mul-float/2addr v0, p0

    invoke-static {p1, p2}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p1

    mul-float/2addr p1, p0

    invoke-static {v0, p1}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p0

    return-wide p0
.end method

.method public static final OooOoo0(Ljava/lang/Object;)V
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/ts7;

    if-nez v0, :cond_0

    return-void

    :cond_0
    check-cast p0, Llyiahf/vczjk/ts7;

    iget-object p0, p0, Llyiahf/vczjk/ts7;->exception:Ljava/lang/Throwable;

    throw p0
.end method

.method public static final OooOooO(JLlyiahf/vczjk/dy6;)J
    .locals 2

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v0

    invoke-static {p0, p1}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result p0

    invoke-interface {p2, v0, p0}, Llyiahf/vczjk/dy6;->OooO00o(FF)J

    move-result-wide p0

    const/16 p2, 0x20

    shr-long v0, p0, p2

    long-to-int p2, v0

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    const-wide v0, 0xffffffffL

    and-long/2addr p0, v0

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    invoke-static {p2, p0}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide p0

    return-wide p0
.end method


# virtual methods
.method public abstract OooO0oO()Ljava/lang/Object;
.end method

.method public abstract OooOo(Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/rl6;
.end method

.method public abstract OooOo00()V
.end method

.method public abstract OooOoO(Z)V
.end method

.method public OooOoO0(Z)V
    .locals 0

    return-void
.end method

.method public abstract OooOoOO()V
.end method
