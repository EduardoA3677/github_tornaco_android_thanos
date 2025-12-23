.class public abstract Llyiahf/vczjk/kh6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/os8;Ljava/util/List;Llyiahf/vczjk/sg1;)V
    .locals 5

    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_3

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/d7;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/os8;->OooO0OO(Llyiahf/vczjk/d7;)I

    move-result v2

    invoke-virtual {p0, v2}, Llyiahf/vczjk/os8;->OooOOo0(I)I

    move-result v3

    iget-object v4, p0, Llyiahf/vczjk/os8;->OooO0O0:[I

    invoke-virtual {p0, v4, v3}, Llyiahf/vczjk/os8;->Oooo0OO([II)I

    move-result v3

    iget-object v4, p0, Llyiahf/vczjk/os8;->OooO0O0:[I

    add-int/lit8 v2, v2, 0x1

    invoke-virtual {p0, v2}, Llyiahf/vczjk/os8;->OooOOo0(I)I

    move-result v2

    invoke-virtual {p0, v4, v2}, Llyiahf/vczjk/os8;->OooO0o([II)I

    move-result v2

    if-ge v3, v2, :cond_0

    invoke-virtual {p0, v3}, Llyiahf/vczjk/os8;->OooO0oO(I)I

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/os8;->OooO0OO:[Ljava/lang/Object;

    aget-object v2, v3, v2

    goto :goto_1

    :cond_0
    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    :goto_1
    instance-of v3, v2, Llyiahf/vczjk/aj7;

    if-eqz v3, :cond_1

    check-cast v2, Llyiahf/vczjk/aj7;

    goto :goto_2

    :cond_1
    const/4 v2, 0x0

    :goto_2
    if-eqz v2, :cond_2

    iput-object p2, v2, Llyiahf/vczjk/aj7;->OooO0O0:Llyiahf/vczjk/sg1;

    :cond_2
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_3
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/j28;Llyiahf/vczjk/cm4;Ljava/util/List;Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/rf1;I)V
    .locals 12

    move-object v2, p3

    move-object/from16 v9, p5

    check-cast v9, Llyiahf/vczjk/zf1;

    const v0, 0x1c746128

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p6, v0

    invoke-virtual {v9, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x20

    goto :goto_1

    :cond_1
    const/16 v3, 0x10

    :goto_1
    or-int/2addr v0, v3

    invoke-virtual {v9, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    invoke-virtual {v9, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x800

    goto :goto_3

    :cond_3
    const/16 v4, 0x400

    :goto_3
    or-int/2addr v0, v4

    move-object/from16 v6, p4

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    const/16 v4, 0x4000

    goto :goto_4

    :cond_4
    const/16 v4, 0x2000

    :goto_4
    or-int/2addr v0, v4

    and-int/lit16 v0, v0, 0x2493

    const/16 v4, 0x2492

    if-ne v0, v4, :cond_6

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v7, v9

    goto :goto_6

    :cond_6
    :goto_5
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    move-object v4, v0

    check-cast v4, Landroid/content/Context;

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->title_package_sets:I

    invoke-static {v0, v9}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    const v7, 0x4c5de2

    invoke-virtual {v9, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_7

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v7, :cond_8

    :cond_7
    new-instance v8, Llyiahf/vczjk/qz7;

    const/4 v7, 0x0

    invoke-direct {v8, p3, v7}, Llyiahf/vczjk/qz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v8, Llyiahf/vczjk/oe3;

    const/4 v7, 0x0

    invoke-virtual {v9, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v10, 0x1c

    const/4 v11, 0x0

    invoke-static {v0, v11, v8, v9, v10}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v0

    invoke-static {v0, v9, v7}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    iget-boolean v7, p0, Llyiahf/vczjk/j28;->OooO0OO:Z

    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v10

    move-object v7, v0

    new-instance v0, Llyiahf/vczjk/sh3;

    const/4 v8, 0x1

    move-object v3, p0

    move-object v5, p1

    move-object v1, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/sh3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v1, -0x69f917fb

    invoke-static {v1, v0, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v6

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/high16 v8, 0x180000

    move-object v7, v9

    const/16 v9, 0x3e

    move-object v0, v10

    invoke-static/range {v0 .. v9}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    :goto_6
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_9

    new-instance v0, Llyiahf/vczjk/nu3;

    const/4 v7, 0x5

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p6

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/nu3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_9
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/j28;Llyiahf/vczjk/cm4;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/i48;Llyiahf/vczjk/rf1;I)V
    .locals 21

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v14, p4

    check-cast v14, Llyiahf/vczjk/zf1;

    const v0, -0x7f647985

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/16 v0, 0x20

    goto :goto_0

    :cond_0
    const/16 v0, 0x10

    :goto_0
    or-int v0, p5, v0

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x100

    goto :goto_1

    :cond_1
    const/16 v5, 0x80

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x800

    goto :goto_2

    :cond_2
    const/16 v5, 0x400

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v5, v0, 0x491

    const/16 v6, 0x490

    if-ne v5, v6, :cond_4

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_4
    :goto_3
    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    const v6, -0x615d173a

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v7, v8

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v7, :cond_5

    if-ne v8, v9, :cond_6

    :cond_5
    new-instance v8, Llyiahf/vczjk/rz7;

    const/4 v7, 0x0

    invoke-direct {v8, v5, v3, v7}, Llyiahf/vczjk/rz7;-><init>(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-virtual {v14, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v5, v8

    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v7, 0x0

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v13, Llyiahf/vczjk/yb1;->OooOOoo:Llyiahf/vczjk/a91;

    const/4 v11, 0x0

    const/4 v12, 0x0

    move v8, v6

    const/4 v6, 0x0

    move v10, v7

    const/4 v7, 0x0

    move v15, v8

    const/4 v8, 0x0

    move-object/from16 v16, v9

    const/4 v9, 0x0

    move/from16 v17, v10

    const/4 v10, 0x0

    move/from16 v18, v15

    const/high16 v15, 0x30000000

    move-object/from16 v19, v16

    const/16 v16, 0x1fe

    move/from16 v1, v17

    move-object/from16 v20, v19

    move/from16 v17, v0

    move/from16 v0, v18

    invoke-static/range {v5 .. v16}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v1, v14}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_create_shortcut_apk:I

    invoke-static {v5, v14}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_7

    move-object/from16 v0, v20

    if-ne v6, v0, :cond_8

    goto :goto_4

    :cond_7
    move-object/from16 v0, v20

    :goto_4
    new-instance v6, Llyiahf/vczjk/gu6;

    const/16 v7, 0x8

    invoke-direct {v6, v7, v4, v3}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v7, 0x1e

    const/4 v8, 0x0

    invoke-static {v5, v8, v6, v14, v7}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v5

    invoke-static {v5, v14, v1}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    const v6, -0x6815fd56

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v6, v17, 0x70

    const/16 v7, 0x20

    if-eq v6, v7, :cond_9

    move v7, v1

    goto :goto_5

    :cond_9
    const/4 v7, 0x1

    :goto_5
    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v6, v7

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v6, v7

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_a

    if-ne v7, v0, :cond_b

    :cond_a
    new-instance v7, Llyiahf/vczjk/x5;

    const/16 v0, 0x10

    invoke-direct {v7, v2, v5, v0, v3}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v5, v7

    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v13, Llyiahf/vczjk/yb1;->OooOo00:Llyiahf/vczjk/a91;

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/high16 v15, 0x30000000

    const/16 v16, 0x1fe

    invoke-static/range {v5 .. v16}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_6
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_c

    new-instance v0, Llyiahf/vczjk/d5;

    const/16 v6, 0xb

    move-object/from16 v1, p0

    move/from16 v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V
    .locals 3

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, 0x28c45083

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    if-ne v0, v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->common_experiment_feature_warning_message:I

    invoke-static {v0, p1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-static {v1, v2, v0, p1, p0}, Llyiahf/vczjk/kh6;->OooO0oO(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_2

    new-instance v0, Llyiahf/vczjk/f16;

    const/4 v1, 0x3

    invoke-direct {v0, p0, p2, v1}, Llyiahf/vczjk/f16;-><init>(Llyiahf/vczjk/kl5;II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2
    return-void
.end method

.method public static final OooO0Oo(Lnow/fortuitous/thanos/sf/SFActivity;Llyiahf/vczjk/rf1;I)V
    .locals 25

    move-object/from16 v0, p0

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x7c406228

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
    or-int v3, p2, v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2

    :cond_2
    :goto_1
    const v3, 0x6e3c21fe

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v6, 0x0

    if-ne v4, v5, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v4

    const-string v7, "sf2"

    invoke-interface {v4, v7, v6}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v4

    xor-int/lit8 v4, v4, 0x1

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    invoke-static {v4}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-static {v2, v6, v3}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v5, :cond_4

    const/16 v7, 0xa

    invoke-static {v7}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object v7

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v7, Llyiahf/vczjk/qr5;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Boolean;

    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    if-eqz v8, :cond_7

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v5, :cond_5

    new-instance v3, Llyiahf/vczjk/oOOO0OO0;

    const/16 v8, 0x16

    invoke-direct {v3, v8}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v8, Llyiahf/vczjk/qw0;

    const/4 v9, 0x7

    invoke-direct {v8, v9, v0, v7, v4}, Llyiahf/vczjk/qw0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/qs5;)V

    const v4, 0x41df290f

    invoke-static {v4, v8, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    new-instance v8, Llyiahf/vczjk/nz7;

    const/4 v9, 0x1

    invoke-direct {v8, v0, v9}, Llyiahf/vczjk/nz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;I)V

    const v9, -0x4a44130

    invoke-static {v9, v8, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    move-object v9, v5

    sget-object v5, Llyiahf/vczjk/yb1;->OooO0O0:Llyiahf/vczjk/a91;

    move v10, v6

    sget-object v6, Llyiahf/vczjk/yb1;->OooO0OO:Llyiahf/vczjk/a91;

    const/16 v17, 0x0

    const v19, 0x361b6

    move-object v11, v7

    const/4 v7, 0x0

    move-object/from16 v18, v2

    move-object v2, v3

    move-object v3, v4

    move-object v4, v8

    move-object v12, v9

    const-wide/16 v8, 0x0

    move v13, v10

    const/4 v10, 0x0

    move-object v15, v11

    move-object v14, v12

    const-wide/16 v11, 0x0

    move/from16 v20, v13

    move-object/from16 v16, v14

    const-wide/16 v13, 0x0

    move-object/from16 v22, v15

    move-object/from16 v21, v16

    const-wide/16 v15, 0x0

    move/from16 v23, v20

    const/16 v20, 0x0

    move-object/from16 v24, v21

    const/16 v21, 0x1fc8

    move-object/from16 v1, v22

    move-object/from16 v0, v24

    invoke-static/range {v2 .. v21}, Llyiahf/vczjk/zsa;->OooOOoo(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JFJJJLlyiahf/vczjk/ab2;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v2, v18

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const v4, 0x4c5de2

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v0, :cond_6

    new-instance v4, Llyiahf/vczjk/vz7;

    const/4 v0, 0x0

    invoke-direct {v4, v1, v0}, Llyiahf/vczjk/vz7;-><init>(Llyiahf/vczjk/qr5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v13, 0x0

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    :cond_7
    :goto_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_8

    new-instance v1, Llyiahf/vczjk/lz7;

    const/4 v2, 0x1

    move-object/from16 v3, p0

    move/from16 v4, p2

    invoke-direct {v1, v3, v4, v2}, Llyiahf/vczjk/lz7;-><init>(Lnow/fortuitous/thanos/sf/SFActivity;II)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void
.end method

.method public static final OooO0o(FF)J
    .locals 4

    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p0

    int-to-long v0, p0

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p0

    int-to-long p0, p0

    const/16 v2, 0x20

    shl-long/2addr v0, v2

    const-wide v2, 0xffffffffL

    and-long/2addr p0, v2

    or-long/2addr p0, v0

    return-wide p0
.end method

.method public static final OooO0o0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 33

    move/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p3

    const-string v3, "back"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v13, p2

    check-cast v13, Llyiahf/vczjk/zf1;

    const v3, 0x6b1fcc38

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v2

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v3, v5

    and-int/lit8 v5, v3, 0x13

    const/16 v7, 0x12

    if-ne v5, v7, :cond_3

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_3
    :goto_2
    sget v5, Llyiahf/vczjk/im4;->OooO0OO:I

    invoke-static {v5, v13}, Llyiahf/vczjk/so8;->OooOo0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v17

    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    const v7, 0x70b323c8

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v13}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v7

    if-eqz v7, :cond_1c

    invoke-static {v7, v13}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v8

    const v9, 0x671a9c9b

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v9, v7, Llyiahf/vczjk/om3;

    if-eqz v9, :cond_4

    move-object v9, v7

    check-cast v9, Llyiahf/vczjk/om3;

    invoke-interface {v9}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v9

    goto :goto_3

    :cond_4
    sget-object v9, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_3
    const-class v10, Llyiahf/vczjk/i48;

    invoke-static {v10, v7, v8, v9, v13}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v7

    const/4 v8, 0x0

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v15, v7

    check-cast v15, Llyiahf/vczjk/i48;

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v7

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/uy4;

    invoke-interface {v7}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v7

    const v9, -0x615d173a

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v14, 0x0

    if-nez v10, :cond_5

    if-ne v11, v12, :cond_6

    :cond_5
    new-instance v11, Llyiahf/vczjk/xz7;

    invoke-direct {v11, v15, v7, v14}, Llyiahf/vczjk/xz7;-><init>(Llyiahf/vczjk/i48;Llyiahf/vczjk/ky4;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v13, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v11, Llyiahf/vczjk/ze3;

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v15, v13, v11}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/z35;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/cp8;

    const v10, -0x6815fd56

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    or-int v11, v11, v16

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    or-int v11, v11, v16

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v11, :cond_7

    if-ne v6, v12, :cond_8

    :cond_7
    new-instance v6, Llyiahf/vczjk/x5;

    const/16 v11, 0x11

    invoke-direct {v6, v7, v15, v11, v5}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v13}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    iget-object v6, v15, Llyiahf/vczjk/i48;->OooOOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v6}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/q29;

    invoke-static {v6, v13}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v18

    iget-object v6, v15, Llyiahf/vczjk/i48;->OooOOo0:Llyiahf/vczjk/sc9;

    invoke-virtual {v6}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/q29;

    invoke-static {v6, v13}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v6

    iget-object v11, v15, Llyiahf/vczjk/i48;->OooOO0:Llyiahf/vczjk/gh7;

    invoke-static {v11, v13}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v11

    new-instance v10, Llyiahf/vczjk/n;

    const/4 v4, 0x1

    invoke-direct {v10, v4}, Llyiahf/vczjk/n;-><init>(I)V

    const v4, 0x4c5de2

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v19, :cond_9

    if-ne v4, v12, :cond_a

    :cond_9
    new-instance v4, Llyiahf/vczjk/qz7;

    const/4 v14, 0x1

    invoke-direct {v4, v15, v14}, Llyiahf/vczjk/qz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v10, v4, v13}, Llyiahf/vczjk/zsa;->o00O0O(Llyiahf/vczjk/n;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/wa5;

    move-result-object v4

    invoke-static {v13}, Llyiahf/vczjk/xr6;->OooOOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/hb8;

    move-result-object v10

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v21

    or-int v14, v14, v21

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v14, :cond_b

    if-ne v9, v12, :cond_c

    :cond_b
    new-instance v9, Llyiahf/vczjk/d08;

    const/4 v14, 0x0

    invoke-direct {v9, v10, v15, v14}, Llyiahf/vczjk/d08;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/i48;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v10, v13, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const v14, -0x615d173a

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v14, v3, 0xe

    const/16 v24, 0x1

    const/4 v8, 0x4

    if-ne v14, v8, :cond_d

    move/from16 v8, v24

    goto :goto_4

    :cond_d
    const/4 v8, 0x0

    :goto_4
    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v8, v14

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v8, :cond_e

    if-ne v14, v12, :cond_f

    :cond_e
    new-instance v14, Llyiahf/vczjk/e08;

    const/4 v8, 0x0

    invoke-direct {v14, v0, v10, v8}, Llyiahf/vczjk/e08;-><init>(ZLlyiahf/vczjk/hb8;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v14, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v13, v14}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_create_shortcut_apk:I

    invoke-static {v8, v13}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    const v14, 0x4c5de2

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    move/from16 v25, v3

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v14, :cond_10

    if-ne v3, v12, :cond_11

    :cond_10
    new-instance v3, Llyiahf/vczjk/kf0;

    const/16 v14, 0x8

    invoke-direct {v3, v8, v14}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v26, Llyiahf/vczjk/wg5;

    const/16 v30, 0x0

    const/16 v31, 0x0

    const-string v27, "install"

    const-string v28, "Install"

    const/16 v29, 0x0

    const/16 v32, 0x1c

    invoke-direct/range {v26 .. v32}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v8, v26

    new-instance v26, Llyiahf/vczjk/wg5;

    const-string v27, "silent_install"

    const-string v28, "Silent Install"

    invoke-direct/range {v26 .. v32}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v14, v26

    filled-new-array {v8, v14}, [Llyiahf/vczjk/wg5;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v8

    const v14, 0x4c5de2

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    move-object/from16 v16, v4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v14, :cond_12

    if-ne v4, v12, :cond_13

    :cond_12
    new-instance v4, Llyiahf/vczjk/sz7;

    const/4 v14, 0x0

    invoke-direct {v4, v15, v14}, Llyiahf/vczjk/sz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v14, 0x0

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v14, v8, v13, v3, v4}, Llyiahf/vczjk/rs;->o000oOoO(ILjava/util/List;Llyiahf/vczjk/rf1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yg5;

    move-result-object v3

    const/16 v4, 0x8

    invoke-static {v3, v13, v4}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    const v14, -0x615d173a

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v4, :cond_14

    if-ne v8, v12, :cond_15

    :cond_14
    new-instance v8, Llyiahf/vczjk/j08;

    const/4 v14, 0x0

    invoke-direct {v8, v15, v3, v14}, Llyiahf/vczjk/j08;-><init>(Llyiahf/vczjk/i48;Llyiahf/vczjk/yg5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v8, Llyiahf/vczjk/ze3;

    const/4 v14, 0x0

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v13, v8}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v10}, Llyiahf/vczjk/hb8;->OooO0OO()Z

    move-result v3

    const v14, 0x4c5de2

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v4, :cond_16

    if-ne v8, v12, :cond_17

    :cond_16
    new-instance v8, Llyiahf/vczjk/n20;

    const/16 v4, 0x10

    invoke-direct {v8, v10, v4}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v8, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v8, v13, v14, v14}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    iget-object v3, v15, Llyiahf/vczjk/i48;->OooOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/q29;

    invoke-static {v3, v13}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v3

    iget-object v4, v15, Llyiahf/vczjk/i48;->OooOOO:Llyiahf/vczjk/gh7;

    invoke-static {v4, v13}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/List;

    new-instance v8, Llyiahf/vczjk/ou;

    const/16 v9, 0x8

    invoke-direct {v8, v11, v9}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    const v9, 0x678889cd

    invoke-static {v9, v8, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    new-instance v14, Llyiahf/vczjk/i08;

    move-object/from16 v21, v5

    move-object/from16 v22, v7

    move-object/from16 v20, v16

    move-object/from16 v19, v17

    move-object/from16 v16, v10

    move-object/from16 v17, v15

    move-object v15, v11

    invoke-direct/range {v14 .. v22}, Llyiahf/vczjk/i08;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/hb8;Llyiahf/vczjk/i48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/cp8;)V

    move-object v5, v15

    move-object/from16 v15, v17

    move-object/from16 v17, v19

    const v7, -0x19cd550a

    invoke-static {v7, v14, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const v9, -0x6815fd56

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    and-int/lit8 v11, v25, 0x70

    const/16 v14, 0x20

    if-ne v11, v14, :cond_18

    goto :goto_5

    :cond_18
    const/16 v24, 0x0

    :goto_5
    or-int v9, v9, v24

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v9, :cond_19

    if-ne v11, v12, :cond_1a

    :cond_19
    new-instance v11, Llyiahf/vczjk/x5;

    const/16 v9, 0x13

    invoke-direct {v11, v15, v1, v9, v5}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v13, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1a
    check-cast v11, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v9, Llyiahf/vczjk/f5;

    const/16 v12, 0x1c

    invoke-direct {v9, v15, v12}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v12, -0x65bed02f

    invoke-static {v12, v9, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    new-instance v14, Llyiahf/vczjk/ha2;

    const/16 v20, 0x3

    move-object/from16 v18, v3

    move-object/from16 v19, v4

    move-object/from16 v16, v5

    invoke-direct/range {v14 .. v20}, Llyiahf/vczjk/ha2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v3, 0x339d82d3

    invoke-static {v3, v14, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    new-instance v18, Llyiahf/vczjk/n6;

    const/16 v19, 0x14

    const/16 v23, 0x0

    move-object/from16 v22, v6

    move-object/from16 v20, v15

    move-object/from16 v21, v16

    invoke-direct/range {v18 .. v23}, Llyiahf/vczjk/n6;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    move-object/from16 v4, v18

    const v5, -0x4b4d3269

    invoke-static {v5, v4, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    const/4 v4, 0x0

    move-object v6, v7

    const/4 v7, 0x0

    const v14, 0x6c301b0

    const/16 v15, 0x9

    move-object v5, v8

    move-object v8, v11

    move-object v11, v3

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_6
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v3

    if-eqz v3, :cond_1b

    new-instance v4, Llyiahf/vczjk/ml4;

    const/4 v5, 0x1

    invoke-direct {v4, v0, v1, v2, v5}, Llyiahf/vczjk/ml4;-><init>(ZLlyiahf/vczjk/le3;II)V

    iput-object v4, v3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1b
    return-void

    :cond_1c
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO0oO(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 24

    move-object/from16 v0, p2

    const-string v1, "text"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v1, p3

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x5fbe8960

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v2, p1, 0x1

    if-eqz v2, :cond_0

    or-int/lit8 v3, p0, 0x6

    move v4, v3

    move-object/from16 v3, p4

    goto :goto_1

    :cond_0
    and-int/lit8 v3, p0, 0x6

    if-nez v3, :cond_2

    move-object/from16 v3, p4

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/4 v4, 0x4

    goto :goto_0

    :cond_1
    const/4 v4, 0x2

    :goto_0
    or-int v4, p0, v4

    goto :goto_1

    :cond_2
    move-object/from16 v3, p4

    move/from16 v4, p0

    :goto_1
    and-int/lit8 v5, p0, 0x30

    const/16 v6, 0x10

    if-nez v5, :cond_4

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    const/16 v5, 0x20

    goto :goto_2

    :cond_3
    move v5, v6

    :goto_2
    or-int/2addr v4, v5

    :cond_4
    and-int/lit8 v5, v4, 0x13

    const/16 v7, 0x12

    if-ne v5, v7, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_5

    goto :goto_3

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v0, v1

    move-object v2, v3

    goto/16 :goto_6

    :cond_6
    :goto_3
    if-eqz v2, :cond_7

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_4

    :cond_7
    move-object v2, v3

    :goto_4
    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v5, 0x18

    int-to-float v5, v5

    invoke-static {v5}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const-wide v7, 0xffffecb3L

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v7

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v3, v7, v8, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const v5, 0x6e3c21fe

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v7, :cond_8

    new-instance v5, Llyiahf/vczjk/oOOO0OO0;

    const/16 v7, 0x16

    invoke-direct {v5, v7}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v7, 0x0

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v5}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v5, v6

    invoke-static {v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v7, 0x36

    invoke-static {v5, v6, v1, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v6, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v1, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_9

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_9
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_a

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_b

    :cond_a
    invoke-static {v6, v1, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0xa

    invoke-static {v3}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v5

    move-object v7, v2

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    shr-int/lit8 v4, v4, 0x3

    and-int/lit8 v4, v4, 0xe

    or-int/lit16 v4, v4, 0x6180

    const/16 v17, 0x0

    const/16 v18, 0x0

    move-object/from16 v19, v1

    const/4 v1, 0x0

    move/from16 v20, v4

    move-wide v4, v5

    const/4 v6, 0x0

    move-object v8, v7

    const/4 v7, 0x0

    move-object v10, v8

    const-wide/16 v8, 0x0

    move-object v11, v10

    const/4 v10, 0x0

    move-object v13, v11

    const-wide/16 v11, 0x0

    move-object v14, v13

    const/4 v13, 0x0

    move-object v15, v14

    const/4 v14, 0x0

    move-object/from16 v16, v15

    const/4 v15, 0x0

    move-object/from16 v21, v16

    const/16 v16, 0x0

    move-object/from16 v22, v21

    const/16 v21, 0x0

    move-object/from16 v23, v22

    const v22, 0x3ffea

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v0, v19

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v2, v23

    :goto_6
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_c

    new-instance v0, Llyiahf/vczjk/iu;

    const/4 v4, 0x3

    move/from16 v1, p0

    move/from16 v3, p1

    move-object/from16 v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/iu;-><init>(ILjava/lang/Object;IILjava/lang/Object;)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/f62;ILlyiahf/vczjk/gy9;Llyiahf/vczjk/mm9;ZI)Llyiahf/vczjk/wj7;
    .locals 1

    if-eqz p3, :cond_0

    iget-object p2, p2, Llyiahf/vczjk/gy9;->OooO0O0:Llyiahf/vczjk/s86;

    invoke-interface {p2, p1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/mm9;->OooO0OO(I)Llyiahf/vczjk/wj7;

    move-result-object p1

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    :goto_0
    sget p2, Llyiahf/vczjk/ii9;->OooO00o:F

    invoke-interface {p0, p2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p0

    iget p2, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    if-eqz p4, :cond_1

    int-to-float p3, p5

    sub-float/2addr p3, p2

    int-to-float v0, p0

    sub-float/2addr p3, v0

    goto :goto_1

    :cond_1
    move p3, p2

    :goto_1
    if-eqz p4, :cond_2

    int-to-float p0, p5

    sub-float/2addr p0, p2

    goto :goto_2

    :cond_2
    int-to-float p0, p0

    add-float/2addr p0, p2

    :goto_2
    new-instance p2, Llyiahf/vczjk/wj7;

    iget p4, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-direct {p2, p3, p4, p0, p1}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    return-object p2
.end method

.method public static final OooOO0o(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;Ljava/util/ArrayList;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/lh6;->OooO0O0(Llyiahf/vczjk/hc3;Ljava/util/ArrayList;)V

    return-void
.end method

.method public static OooOOO0(Landroid/content/Context;)V
    .locals 2

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->common_toast_copied_to_clipboard:I

    invoke-virtual {p0, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x1

    invoke-static {p0, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p0

    invoke-virtual {p0}, Landroid/widget/Toast;->show()V

    return-void
.end method

.method public static OooOOoo([B[BI)S
    .locals 2

    div-int/lit8 v0, p2, 0x8

    rem-int/lit8 v1, p2, 0x8

    aget-byte p1, p1, p2

    and-int/lit16 p1, p1, 0xff

    int-to-short p1, p1

    aget-byte p0, p0, v0

    sget-object p2, Llyiahf/vczjk/t51;->OooO0oo:[I

    aget p2, p2, v1

    and-int/2addr p0, p2

    if-eqz p0, :cond_0

    or-int/lit16 p0, p1, 0x100

    int-to-short p0, p0

    return p0

    :cond_0
    return p1
.end method

.method public static synthetic OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    sget-object p1, Llyiahf/vczjk/e72;->OooOOO0:Llyiahf/vczjk/e72;

    :cond_0
    sget-object p2, Llyiahf/vczjk/jg5;->OooO00o:Llyiahf/vczjk/tp3;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/g13;->OooOoo:Llyiahf/vczjk/g13;

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/mr7;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object p0

    return-object p0
.end method

.method public static OooOoo(C)I
    .locals 3

    add-int/lit16 v0, p0, -0x4e00

    const/16 v1, 0x1b58

    if-ltz v0, :cond_0

    if-ge v0, v1, :cond_0

    sget-object p0, Llyiahf/vczjk/rs;->OooO0Oo:[B

    sget-object v1, Llyiahf/vczjk/rs;->OooO0o0:[B

    invoke-static {p0, v1, v0}, Llyiahf/vczjk/kh6;->OooOOoo([B[BI)S

    move-result p0

    return p0

    :cond_0
    if-gt v1, v0, :cond_1

    const/16 v1, 0x36b0

    if-ge v0, v1, :cond_1

    sget-object v0, Llyiahf/vczjk/ng0;->OooO0o0:[B

    sget-object v1, Llyiahf/vczjk/ng0;->OooO0o:[B

    add-int/lit16 p0, p0, -0x6958

    invoke-static {v0, v1, p0}, Llyiahf/vczjk/kh6;->OooOOoo([B[BI)S

    move-result p0

    return p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/tg0;->OooO0Oo:[B

    sget-object v1, Llyiahf/vczjk/tg0;->OooO0o0:[B

    const v2, 0x84b0

    sub-int/2addr p0, v2

    invoke-static {v0, v1, p0}, Llyiahf/vczjk/kh6;->OooOOoo([B[BI)S

    move-result p0

    return p0
.end method

.method public static final OooOooo(ILlyiahf/vczjk/rf1;)Ljava/lang/String;
    .locals 1

    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO00o:Llyiahf/vczjk/jh1;

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/content/Context;

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    if-nez p0, :cond_0

    sget p0, Landroidx/compose/ui/R$string;->navigation_menu:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 v0, 0x1

    if-ne p0, v0, :cond_1

    sget p0, Landroidx/compose/ui/R$string;->close_drawer:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_1
    const/4 v0, 0x2

    if-ne p0, v0, :cond_2

    sget p0, Landroidx/compose/ui/R$string;->close_sheet:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_2
    const/4 v0, 0x3

    if-ne p0, v0, :cond_3

    sget p0, Landroidx/compose/ui/R$string;->default_error_message:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_3
    const/4 v0, 0x4

    if-ne p0, v0, :cond_4

    sget p0, Landroidx/compose/ui/R$string;->dropdown_menu:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_4
    const/4 v0, 0x5

    if-ne p0, v0, :cond_5

    sget p0, Landroidx/compose/ui/R$string;->range_start:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_5
    const/4 v0, 0x6

    if-ne p0, v0, :cond_6

    sget p0, Landroidx/compose/ui/R$string;->range_end:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_6
    const/4 v0, 0x7

    if-ne p0, v0, :cond_7

    sget p0, Landroidx/compose/material/R$string;->mc2_snackbar_pane_title:I

    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_7
    const-string p0, ""

    return-object p0
.end method

.method public static Oooo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    if-eqz p0, :cond_7

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_2

    :cond_0
    new-instance v0, Ljava/lang/StringBuffer;

    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    const/4 v1, 0x0

    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    if-ge v1, v2, :cond_6

    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    move-result v2

    const/16 v3, 0x4e00

    const/16 v4, 0x3007

    if-gt v3, v2, :cond_1

    const v3, 0x9fa5

    if-gt v2, v3, :cond_1

    invoke-static {v2}, Llyiahf/vczjk/kh6;->OooOoo(C)I

    move-result v3

    if-gtz v3, :cond_2

    :cond_1
    if-ne v4, v2, :cond_4

    :cond_2
    if-ne v2, v4, :cond_3

    const-string v2, "LING"

    goto :goto_1

    :cond_3
    sget-object v3, Llyiahf/vczjk/t51;->OooO:[Ljava/lang/String;

    invoke-static {v2}, Llyiahf/vczjk/kh6;->OooOoo(C)I

    move-result v2

    aget-object v2, v3, v2

    goto :goto_1

    :cond_4
    invoke-static {v2}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    move-result-object v2

    :goto_1
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    add-int/lit8 v2, v2, -0x1

    if-eq v1, v2, :cond_5

    invoke-virtual {v0, p1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    :cond_5
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_6
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    move-result-object p0

    :cond_7
    :goto_2
    return-object p0
.end method

.method public static final Oooo000(Llyiahf/vczjk/mm9;I)Llyiahf/vczjk/rr7;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v0, v0, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    invoke-virtual {v0}, Llyiahf/vczjk/an;->length()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v1

    if-eqz p1, :cond_1

    add-int/lit8 v2, p1, -0x1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v2

    if-eq v1, v2, :cond_2

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v2, v2, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v2, v2, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    if-eq p1, v2, :cond_3

    add-int/lit8 v2, p1, 0x1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v0

    if-eq v1, v0, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {p0, p1}, Llyiahf/vczjk/mm9;->OooO00o(I)Llyiahf/vczjk/rr7;

    move-result-object p0

    return-object p0

    :cond_3
    :goto_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/mm9;->OooO0oO(I)Llyiahf/vczjk/rr7;

    move-result-object p0

    return-object p0
.end method

.method public static final Oooo00O(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Z
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0, p1}, Llyiahf/vczjk/lh6;->OooO00o(Llyiahf/vczjk/hc3;)Z

    move-result p0

    return p0
.end method

.method public static Oooo0OO(Landroid/content/Context;)V
    .locals 2

    const-string v0, "\ud83d\udc4e"

    const/4 v1, 0x1

    invoke-static {p0, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p0

    invoke-virtual {p0}, Landroid/widget/Toast;->show()V

    return-void
.end method

.method public static Oooo0o(Landroid/content/Context;)V
    .locals 2

    const-string v0, "\ud83d\udc4c"

    const/4 v1, 0x1

    invoke-static {p0, v0, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p0

    invoke-virtual {p0}, Landroid/widget/Toast;->show()V

    return-void
.end method

.method public static Oooo0o0(Landroid/content/Context;Ljava/lang/String;)V
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "\ud83d\udc4e\n"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const/4 v0, 0x1

    invoke-static {p0, p1, v0}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p0

    invoke-virtual {p0}, Landroid/widget/Toast;->show()V

    return-void
.end method

.method public static final Oooo0oO(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Ljava/util/ArrayList;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-static {p0, p1, v0}, Llyiahf/vczjk/kh6;->OooOO0o(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;Ljava/util/ArrayList;)V

    return-object v0
.end method

.method public static OoooO0O(Landroid/graphics/Canvas;Ljava/lang/CharSequence;)I
    .locals 4

    instance-of v0, p1, Landroid/text/Spanned;

    if-eqz v0, :cond_3

    check-cast p1, Landroid/text/Spanned;

    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const-class v1, Llyiahf/vczjk/om9;

    const/4 v2, 0x0

    invoke-interface {p1, v2, v0, v1}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/om9;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    array-length v3, v0

    if-lez v3, :cond_0

    aget-object v0, v0, v2

    iget-object v0, v0, Llyiahf/vczjk/om9;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/text/Layout;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/text/Layout;->getWidth()I

    move-result p0

    return p0

    :cond_1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const-class v3, Llyiahf/vczjk/yn9;

    invoke-interface {p1, v2, v0, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Llyiahf/vczjk/yn9;

    if-eqz p1, :cond_2

    array-length v0, p1

    if-lez v0, :cond_2

    aget-object p1, p1, v2

    iget-object p1, p1, Llyiahf/vczjk/yn9;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Landroid/widget/TextView;

    :cond_2
    if-eqz v1, :cond_3

    invoke-virtual {v1}, Landroid/view/View;->getWidth()I

    move-result p0

    invoke-virtual {v1}, Landroid/view/View;->getPaddingLeft()I

    move-result p1

    sub-int/2addr p0, p1

    invoke-virtual {v1}, Landroid/view/View;->getPaddingRight()I

    move-result p1

    sub-int/2addr p0, p1

    return p0

    :cond_3
    invoke-virtual {p0}, Landroid/graphics/Canvas;->getWidth()I

    move-result p0

    return p0
.end method


# virtual methods
.method public abstract OooOO0(Landroid/view/ViewGroup$MarginLayoutParams;)I
.end method

.method public abstract OooOO0O(I)F
.end method

.method public abstract OooOOO(Landroid/content/Context;Llyiahf/vczjk/va3;Landroid/content/res/Resources;I)Landroid/graphics/Typeface;
.end method

.method public abstract OooOOOO(Landroid/content/Context;[Llyiahf/vczjk/kb3;I)Landroid/graphics/Typeface;
.end method

.method public OooOOOo(Landroid/content/Context;Ljava/util/List;I)Landroid/graphics/Typeface;
    .locals 0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "createFromFontInfoWithFallback must only be called on API 29+"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOOo(Landroid/content/Context;Landroid/content/res/Resources;ILjava/lang/String;I)Landroid/graphics/Typeface;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/ok6;->OooOo(Landroid/content/Context;)Ljava/io/File;

    move-result-object p1

    const/4 p4, 0x0

    if-nez p1, :cond_0

    return-object p4

    :cond_0
    :try_start_0
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/ok6;->OooOOo(Ljava/io/File;Landroid/content/res/Resources;I)Z

    move-result p2
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez p2, :cond_1

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object p4

    :cond_1
    :try_start_1
    invoke-virtual {p1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Landroid/graphics/Typeface;->createFromFile(Ljava/lang/String;)Landroid/graphics/Typeface;

    move-result-object p2
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object p2

    :catchall_0
    move-exception p2

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    throw p2

    :catch_0
    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object p4
.end method

.method public OooOOo0(Landroid/content/Context;Ljava/io/InputStream;)Landroid/graphics/Typeface;
    .locals 1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->OooOo(Landroid/content/Context;)Ljava/io/File;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return-object v0

    :cond_0
    :try_start_0
    invoke-static {p2, p1}, Llyiahf/vczjk/ok6;->OooOOoo(Ljava/io/InputStream;Ljava/io/File;)Z

    move-result p2
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez p2, :cond_1

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object v0

    :cond_1
    :try_start_1
    invoke-virtual {p1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Landroid/graphics/Typeface;->createFromFile(Ljava/lang/String;)Landroid/graphics/Typeface;

    move-result-object p2
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object p2

    :catchall_0
    move-exception p2

    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    throw p2

    :catch_0
    invoke-virtual {p1}, Ljava/io/File;->delete()Z

    return-object v0
.end method

.method public abstract OooOo()I
.end method

.method public OooOo00([Llyiahf/vczjk/kb3;I)Llyiahf/vczjk/kb3;
    .locals 10

    new-instance v0, Llyiahf/vczjk/wp3;

    const/16 v1, 0x1a

    invoke-direct {v0, v1}, Llyiahf/vczjk/wp3;-><init>(I)V

    and-int/lit8 v0, p2, 0x1

    if-nez v0, :cond_0

    const/16 v0, 0x190

    goto :goto_0

    :cond_0
    const/16 v0, 0x2bc

    :goto_0
    and-int/lit8 p2, p2, 0x2

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz p2, :cond_1

    move p2, v1

    goto :goto_1

    :cond_1
    move p2, v2

    :goto_1
    array-length v3, p1

    const/4 v4, 0x0

    const v5, 0x7fffffff

    move v6, v2

    :goto_2
    if-ge v6, v3, :cond_5

    aget-object v7, p1, v6

    iget v8, v7, Llyiahf/vczjk/kb3;->OooO0OO:I

    sub-int/2addr v8, v0

    invoke-static {v8}, Ljava/lang/Math;->abs(I)I

    move-result v8

    mul-int/lit8 v8, v8, 0x2

    iget-boolean v9, v7, Llyiahf/vczjk/kb3;->OooO0Oo:Z

    if-ne v9, p2, :cond_2

    move v9, v2

    goto :goto_3

    :cond_2
    move v9, v1

    :goto_3
    add-int/2addr v8, v9

    if-eqz v4, :cond_3

    if-le v5, v8, :cond_4

    :cond_3
    move-object v4, v7

    move v5, v8

    :cond_4
    add-int/lit8 v6, v6, 0x1

    goto :goto_2

    :cond_5
    return-object v4
.end method

.method public abstract OooOo0O(Landroid/view/ViewGroup$MarginLayoutParams;)I
.end method

.method public abstract OooOo0o()I
.end method

.method public abstract OooOoO()I
.end method

.method public abstract OooOoO0()I
.end method

.method public abstract OooOoOO(Landroid/view/View;)I
.end method

.method public abstract OooOoo0(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)I
.end method

.method public abstract OooOooO()I
.end method

.method public abstract Oooo0(Landroid/view/View;)Z
.end method

.method public abstract Oooo00o(F)Z
.end method

.method public abstract Oooo0O0(FF)Z
.end method

.method public abstract Oooo0oo(Landroid/view/View;F)Z
.end method

.method public abstract OoooO0(Landroid/view/ViewGroup$MarginLayoutParams;II)V
.end method

.method public abstract OoooO00(Landroid/view/ViewGroup$MarginLayoutParams;I)V
.end method
