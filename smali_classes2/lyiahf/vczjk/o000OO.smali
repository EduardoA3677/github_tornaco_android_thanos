.class public final synthetic Llyiahf/vczjk/o000OO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o000OO;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o000OO;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-string v2, "getAppLabel(...)"

    const/high16 v3, 0x3f800000    # 1.0f

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x1

    const-string v7, "it"

    sget-object v8, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v9, v0, Llyiahf/vczjk/o000OO;->OooOOO:Ljava/lang/Object;

    iget v10, v0, Llyiahf/vczjk/o000OO;->OooOOO0:I

    packed-switch v10, :pswitch_data_0

    check-cast v1, Landroid/content/Context;

    check-cast v9, Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    invoke-virtual {v9}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getLabel()Ljava/lang/String;

    move-result-object v1

    const-string v2, "getLabel(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v1

    :pswitch_0
    check-cast v1, Ljava/lang/String;

    sget v2, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;->OoooO0O:I

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/on4;

    iget-object v2, v9, Llyiahf/vczjk/on4;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    invoke-virtual {v2, v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->addLaunchOtherAppRule(Ljava/lang/String;)V

    invoke-virtual {v9}, Llyiahf/vczjk/on4;->OooO0o0()V

    return-object v8

    :pswitch_1
    check-cast v1, Ljava/lang/Throwable;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Lgithub/tornaco/android/thanos/core/app/infinite/IRemovePackageCallback;

    if-eqz v9, :cond_0

    invoke-static {v1}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {v9, v1, v4}, Lgithub/tornaco/android/thanos/core/app/infinite/IRemovePackageCallback;->onError(Ljava/lang/String;I)V

    :cond_0
    return-object v8

    :pswitch_2
    check-cast v1, Llyiahf/vczjk/tm0;

    check-cast v9, Llyiahf/vczjk/vx3;

    iget-object v2, v9, Llyiahf/vczjk/vx3;->Oooo0o0:Llyiahf/vczjk/gi;

    invoke-virtual {v2}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wd2;

    iget v2, v2, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-virtual {v1}, Llyiahf/vczjk/tm0;->OooO0O0()F

    move-result v3

    mul-float/2addr v3, v2

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v2

    iget-object v4, v9, Llyiahf/vczjk/vx3;->Oooo0OO:Llyiahf/vczjk/qj8;

    if-nez v4, :cond_1

    sget-object v4, Llyiahf/vczjk/cl8;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {v9, v4}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/al8;

    sget-object v5, Llyiahf/vczjk/o03;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v4, v5}, Llyiahf/vczjk/cl8;->OooO00o(Llyiahf/vczjk/al8;Llyiahf/vczjk/dk8;)Llyiahf/vczjk/qj8;

    move-result-object v4

    :cond_1
    iget-object v5, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v5}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v7

    iget-object v5, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v5}, Llyiahf/vczjk/qj0;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v5

    invoke-interface {v4, v7, v8, v5, v1}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v4

    instance-of v5, v4, Llyiahf/vczjk/pf6;

    if-eqz v5, :cond_2

    check-cast v4, Llyiahf/vczjk/pf6;

    iget-object v4, v4, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    invoke-static {v2, v4}, Llyiahf/vczjk/bq6;->OooO00o(Llyiahf/vczjk/bq6;Llyiahf/vczjk/wj7;)V

    goto :goto_0

    :cond_2
    instance-of v5, v4, Llyiahf/vczjk/qf6;

    if-eqz v5, :cond_3

    check-cast v4, Llyiahf/vczjk/qf6;

    iget-object v4, v4, Llyiahf/vczjk/qf6;->OooO:Llyiahf/vczjk/nv7;

    invoke-static {v2, v4}, Llyiahf/vczjk/bq6;->OooO0O0(Llyiahf/vczjk/bq6;Llyiahf/vczjk/nv7;)V

    goto :goto_0

    :cond_3
    instance-of v5, v4, Llyiahf/vczjk/of6;

    if-eqz v5, :cond_7

    check-cast v4, Llyiahf/vczjk/of6;

    iget-object v4, v4, Llyiahf/vczjk/of6;->OooO:Llyiahf/vczjk/qe;

    invoke-static {v2, v4}, Llyiahf/vczjk/bq6;->OooO0OO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/qe;)V

    :goto_0
    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v4

    iget-object v5, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v5}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v7

    const-wide v10, 0xffffffffL

    and-long/2addr v7, v10

    long-to-int v5, v7

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    sub-float/2addr v5, v3

    iget-object v3, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v3}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v7

    const/16 v3, 0x20

    shr-long/2addr v7, v3

    long-to-int v3, v7

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    iget-object v7, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v7}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v7

    and-long/2addr v7, v10

    long-to-int v7, v7

    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v7

    sget-object v8, Llyiahf/vczjk/yp6;->OooOOO0:[Llyiahf/vczjk/yp6;

    const/4 v8, 0x0

    invoke-static {v8}, Ljava/lang/Float;->isNaN(F)Z

    move-result v10

    if-nez v10, :cond_4

    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    move-result v10

    if-nez v10, :cond_4

    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    move-result v10

    if-nez v10, :cond_4

    invoke-static {v7}, Ljava/lang/Float;->isNaN(F)Z

    move-result v10

    if-eqz v10, :cond_5

    :cond_4
    const-string v10, "Invalid rectangle, make sure no value is NaN"

    invoke-static {v10}, Llyiahf/vczjk/se;->OooO0O0(Ljava/lang/String;)V

    :cond_5
    iget-object v10, v4, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    if-nez v10, :cond_6

    new-instance v10, Landroid/graphics/RectF;

    invoke-direct {v10}, Landroid/graphics/RectF;-><init>()V

    iput-object v10, v4, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    :cond_6
    iget-object v10, v4, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    invoke-static {v10}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v10, v8, v5, v3, v7}, Landroid/graphics/RectF;->set(FFFF)V

    iget-object v3, v4, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v5, Landroid/graphics/Path$Direction;->CCW:Landroid/graphics/Path$Direction;

    iget-object v7, v4, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    invoke-virtual {v7, v3, v5}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v3

    invoke-virtual {v3, v4, v2, v6}, Llyiahf/vczjk/qe;->OooO0oO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/bq6;I)Z

    new-instance v2, Llyiahf/vczjk/o0OO000o;

    const/16 v4, 0x11

    invoke-direct {v2, v4, v3, v9}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v1

    return-object v1

    :cond_7
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_3
    check-cast v1, Llyiahf/vczjk/af8;

    const-string v2, "$this$semantics"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/hv3;

    iget-object v2, v9, Llyiahf/vczjk/hv3;->OooO0O0:Ljava/lang/String;

    invoke-static {v1, v2}, Llyiahf/vczjk/ye8;->OooO0Oo(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    const/4 v2, 0x5

    invoke-static {v1, v2}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    return-object v8

    :pswitch_4
    check-cast v1, Ljava/lang/Throwable;

    check-cast v9, Llyiahf/vczjk/k43;

    iput-object v1, v9, Llyiahf/vczjk/k43;->OooOOoo:Ljava/lang/Throwable;

    return-object v8

    :pswitch_5
    check-cast v9, [Z

    check-cast v1, Ljava/io/File;

    invoke-static {v9, v1}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->OooO00o([ZLjava/io/File;)Llyiahf/vczjk/z8a;

    move-result-object v1

    return-object v1

    :pswitch_6
    check-cast v1, Ljava/io/IOException;

    check-cast v9, Llyiahf/vczjk/cc2;

    iput-boolean v6, v9, Llyiahf/vczjk/cc2;->OooOo0o:Z

    return-object v8

    :pswitch_7
    check-cast v1, Ljava/lang/Float;

    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    move-result v1

    check-cast v9, Llyiahf/vczjk/l1a;

    iget-object v2, v9, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    invoke-interface {v2}, Llyiahf/vczjk/jx9;->getState()Llyiahf/vczjk/kx9;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/kx9;->OooO0O0()F

    move-result v3

    add-float/2addr v3, v1

    invoke-virtual {v2, v3}, Llyiahf/vczjk/kx9;->OooO0Oo(F)V

    return-object v8

    :pswitch_8
    check-cast v1, Llyiahf/vczjk/j48;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/rw7;

    invoke-virtual {v9}, Llyiahf/vczjk/rw7;->call()Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_9
    check-cast v1, Landroid/view/View;

    const-string v2, "view"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v2, Lgithub/tornaco/android/thanos/R$id;->outputTextView:I

    invoke-virtual {v1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    check-cast v9, Llyiahf/vczjk/dj1;

    iget-object v2, v9, Llyiahf/vczjk/dj1;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    return-object v8

    :pswitch_a
    check-cast v1, Ljava/lang/String;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/fj1;

    iget-object v2, v9, Llyiahf/vczjk/fj1;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dj1;

    const/4 v4, 0x2

    invoke-static {v3, v1, v5, v4}, Llyiahf/vczjk/dj1;->OooO00o(Llyiahf/vczjk/dj1;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/dj1;

    move-result-object v1

    invoke-virtual {v2, v5, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-object v8

    :pswitch_b
    check-cast v1, Llyiahf/vczjk/iu0;

    sget v2, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;->OoooO0O:I

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;

    invoke-static {v9}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v2

    iget-object v1, v1, Llyiahf/vczjk/iu0;->OooO00o:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v2, v1}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v1

    invoke-static {v9, v1}, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OooOoo(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    return-object v8

    :pswitch_c
    check-cast v1, Llyiahf/vczjk/gj2;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/gj2;->OooO0O0:Ljava/lang/Enum;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/y03;

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/t81;

    const-string v1, "filter"

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_8
    iget-object v1, v3, Llyiahf/vczjk/t81;->OooOO0:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/y03;

    invoke-virtual {v1, v4, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_8

    return-object v8

    :pswitch_d
    check-cast v1, Llyiahf/vczjk/c0a;

    const-string v2, "null cannot be cast to non-null type androidx.compose.material3.internal.ParentSemanticsNode"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/ep6;

    iput-boolean v6, v1, Llyiahf/vczjk/ep6;->OooOoo0:Z

    iget-object v2, v1, Llyiahf/vczjk/ep6;->OooOoOO:Llyiahf/vczjk/oe3;

    check-cast v9, Llyiahf/vczjk/af8;

    invoke-interface {v2, v9}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object v1

    :pswitch_e
    check-cast v1, Llyiahf/vczjk/fv4;

    const-string v2, "$this$LazyColumn"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v2, Lnow/fortuitous/thanos/settings/BuildPropActivity;->Oooo00O:I

    check-cast v9, Lnow/fortuitous/thanos/settings/BuildPropActivity;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-class v2, Lgithub/tornaco/android/thanos/BuildProp;

    invoke-virtual {v2}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v2

    const-string v3, "getDeclaredFields(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    array-length v7, v2

    invoke-direct {v3, v7}, Ljava/util/ArrayList;-><init>(I)V

    array-length v7, v2

    :goto_1
    if-ge v4, v7, :cond_a

    aget-object v10, v2, v4

    invoke-virtual {v10, v6}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    invoke-virtual {v10}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v10, v5}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    if-nez v10, :cond_9

    const-string v10, ""

    :cond_9
    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v10

    new-instance v12, Llyiahf/vczjk/xn6;

    invoke-direct {v12, v11, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/2addr v4, v6

    goto :goto_1

    :cond_a
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v2

    new-instance v4, Llyiahf/vczjk/tj0;

    invoke-direct {v4, v3}, Llyiahf/vczjk/tj0;-><init>(Ljava/util/ArrayList;)V

    new-instance v7, Llyiahf/vczjk/uj0;

    invoke-direct {v7, v3, v9}, Llyiahf/vczjk/uj0;-><init>(Ljava/util/ArrayList;Lnow/fortuitous/thanos/settings/BuildPropActivity;)V

    new-instance v3, Llyiahf/vczjk/a91;

    const v9, -0x25b7f321

    invoke-direct {v3, v9, v7, v6}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v2, v5, v4, v3}, Llyiahf/vczjk/fv4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    return-object v8

    :pswitch_f
    check-cast v1, Llyiahf/vczjk/gi;

    check-cast v9, Llyiahf/vczjk/i80;

    iget-object v2, v9, Llyiahf/vczjk/i80;->Oooo0O0:Llyiahf/vczjk/lr5;

    invoke-virtual {v1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    rem-float/2addr v1, v3

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-object v8

    :pswitch_10
    check-cast v1, Llyiahf/vczjk/gi;

    check-cast v9, Llyiahf/vczjk/i70;

    iget-object v2, v9, Llyiahf/vczjk/i70;->Oooo0o0:Llyiahf/vczjk/lr5;

    invoke-virtual {v1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    rem-float/2addr v1, v3

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-object v8

    :pswitch_11
    check-cast v1, Landroid/content/Context;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/zt;

    iget-object v2, v9, Llyiahf/vczjk/zt;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    return-object v1

    :pswitch_12
    check-cast v1, Llyiahf/vczjk/z8a;

    check-cast v9, Llyiahf/vczjk/xw;

    iget-object v1, v9, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v1

    :pswitch_13
    check-cast v1, Landroid/content/Context;

    sget v2, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/AppLockListActivity;->OoooO:I

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/ep;

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->nav_title_settings:I

    invoke-virtual {v1, v3}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v1

    const-string v3, "getString(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget v3, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_settings_2_fill:I

    new-instance v4, Llyiahf/vczjk/k1;

    check-cast v9, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/AppLockListActivity;

    const/4 v5, 0x7

    invoke-direct {v4, v9, v5}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v2, v1, v3, v4}, Llyiahf/vczjk/ep;-><init>(Ljava/lang/String;ILlyiahf/vczjk/le3;)V

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    return-object v1

    :pswitch_14
    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    check-cast v9, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v9}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v1

    :pswitch_15
    move-object v14, v1

    check-cast v14, Llyiahf/vczjk/nw;

    invoke-static {v14, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v1, v9

    check-cast v1, Llyiahf/vczjk/dv;

    iget-object v2, v1, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/xu;

    const/4 v12, 0x0

    const/16 v16, 0x2f

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    invoke-static/range {v9 .. v16}, Llyiahf/vczjk/xu;->OooO00o(Llyiahf/vczjk/xu;ZLjava/util/ArrayList;ILjava/lang/String;Llyiahf/vczjk/nw;Ljava/util/List;I)Llyiahf/vczjk/xu;

    move-result-object v3

    invoke-virtual {v2, v5, v3}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-virtual {v1}, Llyiahf/vczjk/dv;->OooO0o()V

    return-object v8

    :pswitch_16
    check-cast v1, Landroidx/activity/result/ActivityResult;

    sget v2, Lnow/fortuitous/thanos/launchother/AllowListActivity;->OoooO0O:I

    const-string v2, "result"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v1, Landroidx/activity/result/ActivityResult;->OooOOO:Landroid/content/Intent;

    if-eqz v1, :cond_b

    const-string v2, "apps"

    invoke-virtual {v1, v2}, Landroid/content/Intent;->getParcelableArrayListExtra(Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object v1

    if-eqz v1, :cond_b

    goto :goto_2

    :cond_b
    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_2
    check-cast v9, Llyiahf/vczjk/w6;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_c

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v3, v9, Llyiahf/vczjk/w6;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v3

    iget-object v4, v9, Llyiahf/vczjk/w6;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v4, v4, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t6;

    iget-object v4, v4, Llyiahf/vczjk/t6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v4

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v2

    invoke-virtual {v3, v4, v2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->addPkgToLaunchOtherAppAllowList(Lgithub/tornaco/android/thanos/core/pm/Pkg;Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    goto :goto_3

    :cond_c
    invoke-virtual {v9}, Llyiahf/vczjk/w6;->OooO0oo()V

    return-object v8

    :pswitch_17
    check-cast v1, Ljava/lang/String;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/n3;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v9, Llyiahf/vczjk/n3;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-object v8

    :pswitch_18
    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    sget v2, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    check-cast v9, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    invoke-virtual {v9, v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setLaunchOtherAppBlockerEnabled(Z)V

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v1

    :pswitch_19
    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    sget v2, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    check-cast v9, Lgithub/tornaco/android/thanos/core/n/NotificationManager;

    invoke-virtual {v9, v1}, Lgithub/tornaco/android/thanos/core/n/NotificationManager;->setScreenOnNotificationEnabled(Z)V

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v1

    :pswitch_1a
    check-cast v1, Llyiahf/vczjk/d52;

    check-cast v9, Llyiahf/vczjk/oOo0o00;

    invoke-virtual {v9}, Llyiahf/vczjk/oOo0o00;->run()V

    return-object v5

    :pswitch_1b
    check-cast v1, Ljava/util/Map$Entry;

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/o00O00OO;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v3

    const-string v4, "(this Map)"

    if-ne v3, v9, :cond_d

    move-object v3, v4

    goto :goto_4

    :cond_d
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    :goto_4
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v3, 0x3d

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v9, :cond_e

    goto :goto_5

    :cond_e
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    :goto_5
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    return-object v1

    :pswitch_1c
    check-cast v9, Llyiahf/vczjk/o0000O;

    if-ne v1, v9, :cond_f

    const-string v1, "(this Collection)"

    goto :goto_6

    :cond_f
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    :goto_6
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
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
