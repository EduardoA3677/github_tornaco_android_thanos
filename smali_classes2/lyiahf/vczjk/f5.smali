.class public final Llyiahf/vczjk/f5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/f5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final OooO0oO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_1

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->message_multiple_patch_applied_error:I

    move-object/from16 v2, p0

    iget-object v3, v2, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    move-object v4, v3

    check-cast v4, Ljava/util/List;

    const/4 v7, 0x0

    const/16 v9, 0x3e

    const-string v5, " "

    const/4 v6, 0x0

    const/4 v8, 0x0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v3, v0}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    const/16 v21, 0x0

    const v22, 0x3fffe

    move-object/from16 v19, v0

    move-object v0, v1

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v20, 0x0

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.method private final OooO0oo(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v0, "app"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/gw6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/gw6;->OooO0oO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ot6;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ot6;

    iget-object v2, v2, Llyiahf/vczjk/ot6;->OooO0O0:Ljava/util/List;

    invoke-static {v2}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v2

    if-eqz p2, :cond_0

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    if-nez p2, :cond_1

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_1
    :goto_0
    const/16 p1, 0xd

    const/4 p2, 0x0

    const/4 v3, 0x0

    invoke-static {v1, p2, v2, v3, p1}, Llyiahf/vczjk/ot6;->OooO00o(Llyiahf/vczjk/ot6;ZLjava/util/ArrayList;Llyiahf/vczjk/mw;I)Llyiahf/vczjk/ot6;

    move-result-object p1

    invoke-virtual {v0, v3, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_1
    :goto_0
    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v0, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v1, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v2, 0x0

    invoke-static {v0, v1, p1, v2}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v0

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/zf1;

    iget v3, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_2

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_4

    :cond_3
    invoke-static {v3, v1, v3, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const p2, 0x4b604343    # 1.4697283E7f

    invoke-virtual {v1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/r17;

    iget-object p2, p2, Llyiahf/vczjk/r17;->OooO0o0:Ljava/util/List;

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_2
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/y17;

    invoke-static {v0, p1, v2}, Llyiahf/vczjk/wr6;->OooO0o(Llyiahf/vczjk/y17;Llyiahf/vczjk/rf1;I)V

    goto :goto_2

    :cond_5
    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 p1, 0x1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    check-cast p1, Llyiahf/vczjk/zf1;

    const p2, 0x4c5de2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast p2, Lnow/fortuitous/thanos/process/v2/ProcessManageActivityV2;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v0, :cond_3

    :cond_2
    new-instance v1, Llyiahf/vczjk/fz3;

    const/16 v0, 0x1a

    invoke-direct {v1, p2, v0}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, p1, p2}, Llyiahf/vczjk/xt6;->OooOOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v19, p1

    check-cast v19, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/lit8 v0, v0, 0x3

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    move-object/from16 v0, v19

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    move-object/from16 v0, p0

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object v1, v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v1

    const-string v2, "getAppLabel(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v2, v19

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x4021aeb5

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v18, v3

    check-cast v18, Llyiahf/vczjk/rn9;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v21, 0x0

    const v22, 0x1fffe

    move-object v0, v1

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v20, 0x0

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.method private final OooOOO0(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v3, Llyiahf/vczjk/pb1;->OooO0OO:Llyiahf/vczjk/a91;

    sget-object v4, Llyiahf/vczjk/pb1;->OooO0Oo:Llyiahf/vczjk/a91;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/k77;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_3

    :cond_2
    new-instance v0, Llyiahf/vczjk/z57;

    const/4 p2, 0x0

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/z57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v2, 0x0

    const/16 v7, 0xdb0

    const/4 v1, 0x0

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/wt2;->OooO00o(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v19, p1

    check-cast v19, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/lit8 v0, v0, 0x3

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    move-object/from16 v0, v19

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    move-object/from16 v0, p0

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ltornaco/apps/thanox/running/RunningAppState;

    iget-object v1, v1, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v1

    const-string v2, "getAppLabel(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v21, 0x0

    const v22, 0x3fffe

    move-object v0, v1

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v20, 0x0

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 67

    move-object/from16 v0, p0

    const/16 v2, 0x14

    const/16 v3, 0xc8

    const v4, 0x4c5de2

    const/16 v6, 0x10

    const/high16 v7, 0x3f800000    # 1.0f

    sget-object v8, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v12, 0x0

    sget-object v13, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v14, 0x1

    const/4 v15, 0x0

    const/16 v16, 0x6

    const/4 v5, 0x2

    sget-object v17, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/16 v18, 0xa

    iget-object v1, v0, Llyiahf/vczjk/f5;->OooOOO:Ljava/lang/Object;

    iget v10, v0, Llyiahf/vczjk/f5;->OooOOO0:I

    packed-switch v10, :pswitch_data_0

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v5, :cond_1

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v1, Llyiahf/vczjk/i48;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_2

    if-ne v4, v9, :cond_3

    :cond_2
    new-instance v4, Llyiahf/vczjk/tz7;

    const/4 v3, 0x5

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/tz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object/from16 v18, v4

    check-cast v18, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v26, Llyiahf/vczjk/yb1;->OooOO0:Llyiahf/vczjk/a91;

    const/high16 v28, 0xc00000

    const/16 v29, 0x7e

    const/16 v19, 0x0

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const/16 v25, 0x0

    move-object/from16 v27, v2

    invoke-static/range {v18 .. v29}, Llyiahf/vczjk/v33;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    return-object v17

    :pswitch_0
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_1
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooOOOO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_2
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooOOO0(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_3
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_4
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_5
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooO0oo(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_6
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    if-eq v4, v5, :cond_4

    move v4, v14

    goto :goto_2

    :cond_4
    move v4, v15

    :goto_2
    and-int/2addr v3, v14

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_5

    const-string v3, "indicatorRipple"

    invoke-static {v13, v3}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/px5;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v4, v2}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v4, 0x7

    invoke-static {v12, v4, v15}, Llyiahf/vczjk/zt7;->OooO00o(FIZ)Llyiahf/vczjk/du7;

    move-result-object v4

    check-cast v1, Llyiahf/vczjk/cc5;

    invoke-static {v3, v1, v4}, Landroidx/compose/foundation/OooO0o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v2, v15}, Llyiahf/vczjk/ch0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    goto :goto_3

    :cond_5
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    return-object v17

    :pswitch_7
    invoke-direct/range {p0 .. p2}, Llyiahf/vczjk/f5;->OooO0oO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_8
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v5, :cond_7

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_6

    goto :goto_4

    :cond_6
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_7
    :goto_4
    check-cast v1, Lnow/fortuitous/thanos/main/NavActivity;

    invoke-static {v1, v2, v15}, Llyiahf/vczjk/sb;->OooOO0O(Landroid/app/Activity;Llyiahf/vczjk/rf1;I)V

    :goto_5
    return-object v17

    :pswitch_9
    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v5, :cond_9

    move-object v2, v8

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_8

    goto :goto_6

    :cond_8
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_9
    :goto_6
    check-cast v1, Llyiahf/vczjk/wg5;

    iget-object v1, v1, Llyiahf/vczjk/wg5;->OooO0Oo:Ljava/lang/Integer;

    if-nez v1, :cond_a

    goto :goto_7

    :cond_a
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    invoke-static {v1, v8}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v3

    const/16 v9, 0x30

    const/16 v10, 0xc

    const/4 v4, 0x0

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    invoke-static/range {v3 .. v10}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_7
    return-object v17

    :pswitch_a
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v5, :cond_c

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_b

    goto :goto_8

    :cond_b
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_9

    :cond_c
    :goto_8
    check-cast v1, Llyiahf/vczjk/yg5;

    iget-object v3, v1, Llyiahf/vczjk/yg5;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v1, v1, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    invoke-interface {v3, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-static {v1, v2, v15}, Llyiahf/vczjk/br6;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    :goto_9
    return-object v17

    :pswitch_b
    move-object/from16 v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v8, p2

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    move-result v8

    and-int/lit8 v8, v8, 0x3

    if-ne v8, v5, :cond_e

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v10

    if-nez v10, :cond_d

    goto :goto_a

    :cond_d
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_d

    :cond_e
    :goto_a
    check-cast v4, Llyiahf/vczjk/zf1;

    const v8, 0x6e3c21fe

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    const/4 v10, 0x0

    if-ne v8, v9, :cond_f

    invoke-static {v10}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v8

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v8, Llyiahf/vczjk/qs5;

    invoke-virtual {v4, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v11, -0x615d173a

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v1, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v11, :cond_10

    if-ne v14, v9, :cond_11

    :cond_10
    new-instance v14, Llyiahf/vczjk/fl4;

    invoke-direct {v14, v1, v8, v10}, Llyiahf/vczjk/fl4;-><init>(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v4, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v14, Llyiahf/vczjk/ze3;

    invoke-virtual {v4, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v4, v14}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v13, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    int-to-float v3, v3

    invoke-static {v7, v3, v12, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v6, v6

    invoke-static {v3, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v2, v2

    const/4 v6, 0x1

    invoke-static {v3, v12, v2, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/16 v7, 0x36

    invoke-static {v6, v3, v4, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v6, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v4, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_12

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_b

    :cond_12
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_b
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v4, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v4, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_13

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v12, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_14

    :cond_13
    invoke-static {v6, v4, v6, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v4, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v12, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v14, 0x30

    invoke-static {v12, v2, v4, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v12, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v4, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_15

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_c

    :cond_15
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_c
    invoke-static {v2, v4, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v4, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_16

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_17

    :cond_16
    invoke-static {v12, v4, v12, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_17
    invoke-static {v13, v4, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v2, v1, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;->OooOOO0:Ljava/lang/String;

    sget-object v3, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n6a;

    iget-object v3, v3, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    sget-object v23, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    const/16 v31, 0x0

    const v32, 0xfffffb

    const-wide/16 v19, 0x0

    const-wide/16 v21, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const-wide/16 v28, 0x0

    const/16 v30, 0x0

    move-object/from16 v18, v3

    invoke-static/range {v18 .. v32}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v38

    const/16 v41, 0x0

    const v42, 0x1fffe

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const-wide/16 v31, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v40, 0x0

    move-object/from16 v20, v2

    move-object/from16 v39, v4

    invoke-static/range {v20 .. v42}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    const/4 v2, 0x2

    invoke-static {v1, v10, v4, v15, v2}, Llyiahf/vczjk/zsa;->OooO0oo(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;II)V

    const/4 v6, 0x1

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO00o(ILlyiahf/vczjk/rf1;)V

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v20, v1

    check-cast v20, Lgithub/tornaco/thanos/module/component/manager/redesign/RuleDescription;

    sget-object v26, Llyiahf/vczjk/pa1;->OooO00o:Llyiahf/vczjk/a91;

    const/high16 v28, 0x180000

    const/16 v29, 0x3e

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    move-object/from16 v27, v4

    invoke-static/range {v20 .. v29}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    const/4 v6, 0x1

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_d
    return-object v17

    :pswitch_c
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    const/4 v4, 0x2

    if-ne v3, v4, :cond_19

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_18

    goto :goto_e

    :cond_18
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_12

    :cond_19
    :goto_e
    sget-object v3, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v14, 0x30

    invoke-static {v4, v3, v2, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    iget v5, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v2, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_1a

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_f

    :cond_1a
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_f
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_1b

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_1c

    :cond_1b
    invoke-static {v5, v4, v5, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    check-cast v1, Llyiahf/vczjk/gj2;

    iget-object v7, v1, Llyiahf/vczjk/gj2;->OooO0OO:Llyiahf/vczjk/ze3;

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-interface {v7, v2, v10}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/16 v7, 0x8

    int-to-float v7, v7

    invoke-static {v13, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-static {v2, v7}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v7, 0x4

    int-to-float v7, v7

    const/4 v10, 0x1

    invoke-static {v13, v12, v7, v10}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v10, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v11, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v10, v11, v2, v15}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v10

    iget v11, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v2, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_1d

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_1d
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    invoke-static {v10, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_1e

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v3, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1f

    :cond_1e
    invoke-static {v11, v4, v11, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1f
    invoke-static {v7, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v1, v1, Llyiahf/vczjk/gj2;->OooO00o:Ljava/util/List;

    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v19, v3

    check-cast v19, Ljava/lang/String;

    sget-object v3, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n6a;

    iget-object v3, v3, Llyiahf/vczjk/n6a;->OooO:Llyiahf/vczjk/rn9;

    const/16 v40, 0x0

    const v41, 0x1fffe

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const-wide/16 v27, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v39, 0x0

    move-object/from16 v38, v2

    move-object/from16 v37, v3

    invoke-static/range {v19 .. v41}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const v2, 0x73771eb4

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, 0x73772897

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    const/4 v6, 0x1

    if-le v2, v6, :cond_21

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    invoke-interface {v1, v6, v2}, Ljava/util/List;->subList(II)Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_20

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v19, v2

    check-cast v19, Ljava/lang/String;

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    invoke-static/range {v18 .. v18}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v23

    const/16 v33, 0x0

    const v34, 0xfffffd

    const-wide/16 v21, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const-wide/16 v28, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    move-object/from16 v20, v2

    invoke-static/range {v20 .. v34}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v37

    const/16 v40, 0x0

    const v41, 0x1fffe

    const/16 v20, 0x0

    const-wide/16 v23, 0x0

    const-wide/16 v27, 0x0

    const/16 v29, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v39, 0x0

    invoke-static/range {v19 .. v41}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    goto :goto_11

    :cond_20
    const/4 v6, 0x1

    :cond_21
    invoke-static {v4, v15, v6, v6}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_12
    return-object v17

    :pswitch_d
    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v4, 0x2

    if-ne v2, v4, :cond_23

    move-object v2, v12

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_22

    goto :goto_13

    :cond_22
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_15

    :cond_23
    :goto_13
    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v14, 0x30

    invoke-static {v3, v2, v12, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v3, v12

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v12, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_24

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_24
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v12, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v12, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_25

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_26

    :cond_25
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_26
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v12, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    check-cast v1, Llyiahf/vczjk/ah5;

    iget v2, v1, Llyiahf/vczjk/ah5;->OooO0OO:I

    invoke-static {v2, v12}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v7

    const/4 v13, 0x0

    const/16 v14, 0xc

    iget-object v8, v1, Llyiahf/vczjk/ah5;->OooO0O0:Ljava/lang/String;

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    invoke-static/range {v7 .. v14}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-static {v15, v12}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    const/16 v39, 0x0

    const v40, 0x3fffe

    iget-object v1, v1, Llyiahf/vczjk/ah5;->OooO0O0:Ljava/lang/String;

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const/16 v28, 0x0

    const-wide/16 v29, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v38, 0x0

    move-object/from16 v18, v1

    move-object/from16 v37, v12

    invoke-static/range {v18 .. v40}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v6, 0x1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_15
    return-object v17

    :pswitch_e
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    const/4 v4, 0x2

    if-ne v3, v4, :cond_28

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_27

    goto :goto_16

    :cond_27
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_17

    :cond_28
    :goto_16
    check-cast v1, Llyiahf/vczjk/p97;

    iget-object v1, v1, Llyiahf/vczjk/p97;->OooO0O0:Ljava/lang/String;

    invoke-static {v1, v2, v15}, Llyiahf/vczjk/br6;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    :goto_17
    return-object v17

    :pswitch_f
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_29

    const/4 v15, 0x1

    :cond_29
    const/16 v43, 0x1

    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v15}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_2d

    sget-object v3, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    check-cast v1, Llyiahf/vczjk/l1a;

    const/16 v7, 0x36

    invoke-static {v3, v4, v2, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v2, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_2a

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_18

    :cond_2a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_18
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_2b

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_2c

    :cond_2b
    invoke-static {v4, v2, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2c
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/l1a;->OooOO0o:Llyiahf/vczjk/bf3;

    invoke-interface {v1, v8, v2, v3}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v6, 0x1

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_19

    :cond_2d
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_19
    return-object v17

    :pswitch_10
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_2e

    const/4 v15, 0x1

    :cond_2e
    const/16 v43, 0x1

    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v15}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_32

    sget-object v3, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    check-cast v1, Llyiahf/vczjk/zp8;

    const/16 v7, 0x36

    invoke-static {v3, v4, v2, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v2, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_2f

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1a

    :cond_2f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1a
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_30

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_31

    :cond_30
    invoke-static {v4, v2, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_31
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/zp8;->OooO0o:Llyiahf/vczjk/a91;

    invoke-virtual {v1, v8, v2, v3}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v6, 0x1

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1b

    :cond_32
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1b
    return-object v17

    :pswitch_11
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_33

    const/4 v4, 0x1

    :goto_1c
    const/16 v43, 0x1

    goto :goto_1d

    :cond_33
    move v4, v15

    goto :goto_1c

    :goto_1d
    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_37

    invoke-static {v13, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    check-cast v1, Llyiahf/vczjk/mx5;

    iget-object v4, v1, Llyiahf/vczjk/mx5;->OooO0o0:Llyiahf/vczjk/zy4;

    invoke-static {v3, v4}, Llyiahf/vczjk/uoa;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kna;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget v4, Llyiahf/vczjk/hx5;->OooO00o:F

    const/4 v6, 0x1

    invoke-static {v3, v12, v4, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0O0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/o68;->OooOoO0:Llyiahf/vczjk/o68;

    invoke-static {v3, v15, v4}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget v4, Llyiahf/vczjk/hx5;->OooO0O0:F

    invoke-static {v4}, Llyiahf/vczjk/tx;->OooO0oO(F)Llyiahf/vczjk/ox;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v7, 0x36

    invoke-static {v4, v5, v2, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v5, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v2, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_34

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1e

    :cond_34
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1e
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_35

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_36

    :cond_35
    invoke-static {v5, v2, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_36
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/mx5;->OooO0o:Llyiahf/vczjk/a91;

    invoke-virtual {v1, v8, v2, v3}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v6, 0x1

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1f

    :cond_37
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1f
    return-object v17

    :pswitch_12
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_38

    const/4 v4, 0x1

    :goto_20
    const/16 v43, 0x1

    goto :goto_21

    :cond_38
    move v4, v15

    goto :goto_20

    :goto_21
    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_3e

    sget v3, Landroidx/compose/material3/R$string;->m3c_dialog:I

    invoke-static {v3, v2}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    check-cast v1, Llyiahf/vczjk/ld9;

    sget v4, Llyiahf/vczjk/j4;->OooO00o:F

    sget v5, Llyiahf/vczjk/j4;->OooO0O0:F

    iget-object v6, v1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/kl5;

    move/from16 v7, v18

    invoke-static {v6, v4, v12, v5, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_3a

    if-ne v6, v9, :cond_39

    goto :goto_22

    :cond_39
    const/4 v10, 0x1

    goto :goto_23

    :cond_3a
    :goto_22
    new-instance v6, Llyiahf/vczjk/kf0;

    const/4 v10, 0x1

    invoke-direct {v6, v3, v10}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_23
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-static {v13, v15, v6}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-interface {v4, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v4, v10}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v5, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v2, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_3b

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_24

    :cond_3b
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_24
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_3c

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_3d

    :cond_3c
    invoke-static {v5, v2, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3d
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/a91;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v6, 0x1

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_25

    :cond_3e
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_25
    return-object v17

    :pswitch_13
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    const/4 v5, 0x2

    if-ne v3, v5, :cond_40

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3f

    goto :goto_26

    :cond_3f
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_27

    :cond_40
    :goto_26
    check-cast v1, Llyiahf/vczjk/ov5;

    invoke-static {v1, v2, v15}, Llyiahf/vczjk/bua;->OooO0oo(Llyiahf/vczjk/ov5;Llyiahf/vczjk/rf1;I)V

    :goto_27
    return-object v17

    :pswitch_14
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_41

    const/4 v15, 0x1

    :cond_41
    const/16 v43, 0x1

    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v15}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_42

    check-cast v1, Llyiahf/vczjk/qz0;

    iget-object v1, v1, Llyiahf/vczjk/qz0;->OooO0OO:Ljava/lang/String;

    const/16 v39, 0x0

    const v40, 0x3fffe

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const/16 v28, 0x0

    const-wide/16 v29, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v38, 0x0

    move-object/from16 v18, v1

    move-object/from16 v37, v2

    invoke-static/range {v18 .. v40}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    goto :goto_28

    :cond_42
    move-object/from16 v37, v2

    invoke-virtual/range {v37 .. v37}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_28
    return-object v17

    :pswitch_15
    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v8, p2

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    move-result v8

    and-int/lit8 v8, v8, 0x3

    const/4 v10, 0x2

    if-ne v8, v10, :cond_44

    move-object v8, v5

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v10

    if-nez v10, :cond_43

    goto :goto_29

    :cond_43
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_31

    :cond_44
    :goto_29
    sget-object v8, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    int-to-float v3, v3

    const/4 v10, 0x2

    invoke-static {v7, v3, v12, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v6, v6

    invoke-static {v3, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v2, v2

    const/4 v6, 0x1

    invoke-static {v3, v12, v2, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/16 v7, 0x36

    invoke-static {v6, v3, v5, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    move-object v10, v5

    check-cast v10, Llyiahf/vczjk/zf1;

    iget v6, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v5, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_45

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2a

    :cond_45
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2a
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v5, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_46

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_47

    :cond_46
    invoke-static {v6, v10, v6, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_47
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v5, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    check-cast v1, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    invoke-virtual {v1}, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v13, ""

    if-nez v2, :cond_48

    move-object/from16 v44, v13

    goto :goto_2b

    :cond_48
    move-object/from16 v44, v2

    :goto_2b
    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object v14, v5

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v4, v16

    check-cast v4, Llyiahf/vczjk/n6a;

    iget-object v4, v4, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    sget-object v32, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    const/16 v40, 0x0

    const v41, 0xfffffb

    const-wide/16 v28, 0x0

    const-wide/16 v30, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const-wide/16 v35, 0x0

    const-wide/16 v37, 0x0

    const/16 v39, 0x0

    move-object/from16 v27, v4

    invoke-static/range {v27 .. v41}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v62

    const/16 v65, 0x0

    const v66, 0x1fffe

    const/16 v45, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const-wide/16 v55, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v64, 0x0

    move-object/from16 v63, v5

    invoke-static/range {v44 .. v66}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v4, v63

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/n6a;

    iget-object v5, v5, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const/16 v65, 0x0

    const v66, 0x1fffe

    const-string v44, "@blocker-general-rules indicator"

    const/16 v45, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const-wide/16 v55, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v64, 0x6

    move-object/from16 v63, v4

    move-object/from16 v62, v5

    invoke-static/range {v44 .. v66}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v1}, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;->getDescription()Ljava/lang/String;

    move-result-object v5

    if-nez v5, :cond_49

    move-object/from16 v44, v13

    goto :goto_2c

    :cond_49
    move-object/from16 v44, v5

    :goto_2c
    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const/16 v65, 0x0

    const v66, 0x1fffe

    const/16 v45, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const-wide/16 v55, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v64, 0x0

    move-object/from16 v62, v2

    move-object/from16 v63, v4

    invoke-static/range {v44 .. v66}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v1}, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;->getSafeToBlock()Z

    move-result v2

    if-eqz v2, :cond_4f

    const v1, -0x714c4c36    # -4.4300037E-30f

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v2, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v14, 0x30

    invoke-static {v2, v1, v4, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v1

    iget v2, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v4, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_4a

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2d

    :cond_4a
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2d
    invoke-static {v1, v4, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v5, v4, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_4b

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4c

    :cond_4b
    invoke-static {v2, v10, v2, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4c
    invoke-static {v13, v4, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_safe_to_block:I

    invoke-static {v1, v4}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v44

    const/16 v65, 0x0

    const v66, 0x3fffe

    const/16 v45, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const-wide/16 v55, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v62, 0x0

    const/16 v64, 0x0

    move-object/from16 v63, v4

    invoke-static/range {v44 .. v66}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    sget v1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_shield_check_fill:I

    invoke-static {v1, v4}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v18

    const-wide v1, 0xff32cd32L

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v21

    const/16 v19, 0x0

    const/16 v24, 0xdb0

    const/16 v25, 0x0

    move-object/from16 v23, v4

    move-object/from16 v20, v8

    invoke-static/range {v18 .. v25}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v6, 0x1

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v15, v4}, Llyiahf/vczjk/ru6;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/content/Context;

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_safe_to_block_tip:I

    invoke-static {v2, v4}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    move-object/from16 v63, v4

    sget-object v4, Llyiahf/vczjk/t91;->OooO00o:Llyiahf/vczjk/a91;

    const v3, 0x4c5de2

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v3, :cond_4d

    if-ne v5, v9, :cond_4e

    :cond_4d
    new-instance v5, Llyiahf/vczjk/kt;

    const/4 v6, 0x1

    invoke-direct {v5, v1, v6}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4e
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v1, v2

    const-wide/16 v2, 0x0

    const/16 v7, 0x180

    const/4 v8, 0x2

    move-object/from16 v6, v63

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/br6;->OooO0o(Ljava/lang/String;JLlyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_2e
    const/4 v6, 0x1

    goto :goto_30

    :cond_4f
    move-object/from16 v63, v4

    invoke-virtual {v1}, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;->getSideEffect()Ljava/lang/String;

    move-result-object v2

    if-nez v2, :cond_50

    goto :goto_2f

    :cond_50
    move-object v13, v2

    :goto_2f
    invoke-virtual {v13}, Ljava/lang/String;->length()I

    move-result v2

    if-lez v2, :cond_51

    const v2, -0x71379ed7

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;->getSideEffect()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Not Safe to block: "

    invoke-static {v2, v1}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v44

    const/16 v65, 0x0

    const v66, 0x3fffe

    const/16 v45, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const-wide/16 v55, 0x0

    const/16 v57, 0x0

    const/16 v58, 0x0

    const/16 v59, 0x0

    const/16 v60, 0x0

    const/16 v61, 0x0

    const/16 v62, 0x0

    const/16 v64, 0x0

    invoke-static/range {v44 .. v66}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2e

    :cond_51
    const v1, -0x71367dca

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2e

    :goto_30
    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_31
    return-object v17

    :pswitch_16
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    const/4 v5, 0x2

    if-ne v3, v5, :cond_53

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_52

    goto :goto_32

    :cond_52
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_34

    :cond_53
    :goto_32
    sget-object v3, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v14, 0x30

    invoke-static {v4, v3, v2, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    iget v5, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v2, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_54

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_33

    :cond_54
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_33
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_55

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v7, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_56

    :cond_55
    invoke-static {v5, v4, v5, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_56
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    check-cast v1, Llyiahf/vczjk/zt;

    iget v3, v1, Llyiahf/vczjk/zt;->OooO0O0:I

    invoke-static {v3, v2}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v18

    int-to-float v3, v6

    invoke-static {v13, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v20

    const/16 v24, 0x1b0

    const/16 v25, 0x0

    const/16 v19, 0x0

    iget-wide v5, v1, Llyiahf/vczjk/zt;->OooO0OO:J

    move-object/from16 v23, v2

    move-wide/from16 v21, v5

    invoke-static/range {v18 .. v25}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-static {v15, v2}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/zt;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v18, v1

    check-cast v18, Ljava/lang/String;

    const/16 v1, 0xc

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v22

    const-wide/high16 v5, 0x4029000000000000L    # 12.5

    invoke-static {v5, v6}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v29

    const/16 v39, 0x30

    const v40, 0x3f7ee

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const/16 v28, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v38, 0x6000

    move-object/from16 v37, v2

    invoke-static/range {v18 .. v40}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v6, 0x1

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_34
    return-object v17

    :pswitch_17
    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v5, 0x2

    if-ne v2, v5, :cond_58

    move-object v2, v12

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_57

    goto :goto_35

    :cond_57
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_36

    :cond_58
    :goto_35
    check-cast v1, Llyiahf/vczjk/ep;

    iget v2, v1, Llyiahf/vczjk/ep;->OooO0O0:I

    invoke-static {v2, v12}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v7

    iget-object v8, v1, Llyiahf/vczjk/ep;->OooO00o:Ljava/lang/String;

    const/4 v13, 0x0

    const/16 v14, 0xc

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    invoke-static/range {v7 .. v14}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_36
    return-object v17

    :pswitch_18
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_59

    const/4 v4, 0x1

    :goto_37
    const/16 v43, 0x1

    goto :goto_38

    :cond_59
    move v4, v15

    goto :goto_37

    :goto_38
    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_5a

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v1, Llyiahf/vczjk/bf3;

    invoke-interface {v1, v8, v2, v3}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_39

    :cond_5a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_39
    return-object v17

    :pswitch_19
    move-object/from16 v2, p1

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-object/from16 v3, p2

    check-cast v3, Lgithub/tornaco/android/thanos/core/ops/PermState;

    const-string v4, "app"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "state"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/dv;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v4, v1, Llyiahf/vczjk/dv;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v4}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    iget-object v5, v1, Llyiahf/vczjk/dv;->OooO0Oo:Llyiahf/vczjk/gh7;

    iget-object v5, v5, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v5, Llyiahf/vczjk/s29;

    invoke-virtual {v5}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/xu;

    iget v5, v5, Llyiahf/vczjk/xu;->OooO0OO:I

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v2

    const-string v6, "fromAppInfo(...)"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v4, v5, v2, v3}, Lgithub/tornaco/android/thanos/core/ops/OpsManager;->setMode(ILgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/dv;->OooO0o()V

    return-object v17

    :pswitch_1a
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x3

    const/4 v5, 0x2

    if-eq v4, v5, :cond_5b

    const/4 v6, 0x1

    :goto_3a
    const/16 v43, 0x1

    goto :goto_3b

    :cond_5b
    move v6, v15

    goto :goto_3a

    :goto_3b
    and-int/lit8 v3, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_5c

    check-cast v1, Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/iq;

    iget-object v1, v1, Llyiahf/vczjk/iq;->OooO00o:Llyiahf/vczjk/jq;

    iget-object v1, v1, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v3

    move v4, v15

    :goto_3c
    if-ge v4, v3, :cond_5d

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qz0;

    invoke-virtual {v5, v15, v2}, Llyiahf/vczjk/qz0;->OooO00o(ILlyiahf/vczjk/rf1;)V

    const/16 v43, 0x1

    add-int/lit8 v4, v4, 0x1

    goto :goto_3c

    :cond_5c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_5d
    return-object v17

    :pswitch_1b
    move-object/from16 v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v5, 0x2

    if-ne v2, v5, :cond_5f

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_5e

    goto :goto_3d

    :cond_5e
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3e

    :cond_5f
    :goto_3d
    const/16 v2, 0xe

    int-to-float v2, v2

    invoke-static {v13, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    check-cast v1, Llyiahf/vczjk/ww2;

    iget v1, v1, Llyiahf/vczjk/ww2;->OooO0Oo:I

    invoke-static {v1, v10}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v5

    sget-wide v8, Llyiahf/vczjk/n21;->OooO0o:J

    const/4 v6, 0x0

    const/16 v11, 0xdb0

    const/4 v12, 0x0

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_3e
    return-object v17

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
