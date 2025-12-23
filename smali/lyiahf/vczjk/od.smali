.class public final Llyiahf/vczjk/od;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/od;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/od;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    const-string v3, "it"

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    const-string v7, "query"

    sget-object v8, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v9, v1, Llyiahf/vczjk/od;->OooOOO:Ljava/lang/Object;

    iget v10, v1, Llyiahf/vczjk/od;->OooOOO0:I

    packed-switch v10, :pswitch_data_0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    check-cast v9, Llyiahf/vczjk/go5;

    iget-object v2, v9, Llyiahf/vczjk/go5;->OooOOO0:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-object v8

    :pswitch_0
    check-cast v0, Llyiahf/vczjk/h55;

    if-nez v0, :cond_0

    goto/16 :goto_1

    :cond_0
    sget-object v2, Llyiahf/vczjk/t19;->OooO00o:Llyiahf/vczjk/on7;

    const-string v2, "line"

    iget-object v0, v0, Llyiahf/vczjk/h55;->OooO0oo:Ljava/lang/String;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/t19;->OooO00o:Llyiahf/vczjk/on7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/on7;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/jd5;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/jd5;->OooO00o()Ljava/util/List;

    move-result-object v2

    invoke-static {v4, v2}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v2, :cond_1

    goto :goto_0

    :cond_1
    sget-object v3, Llyiahf/vczjk/t19;->OooO0O0:Llyiahf/vczjk/on7;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/on7;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/jd5;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/jd5;->OooO00o()Ljava/util/List;

    move-result-object v0

    invoke-static {v4, v0}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    if-eqz v0, :cond_2

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0

    new-instance v6, Llyiahf/vczjk/dn4;

    invoke-direct {v6, v2, v0}, Llyiahf/vczjk/dn4;-><init>(Ljava/lang/String;I)V

    :cond_2
    :goto_0
    if-eqz v6, :cond_4

    check-cast v9, Llyiahf/vczjk/yp9;

    invoke-virtual {v9}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "StartLogParser: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/Logger;->w(Ljava/lang/Object;)V

    iget-object v0, v6, Llyiahf/vczjk/dn4;->OooO00o:Ljava/lang/String;

    iget v2, v6, Llyiahf/vczjk/dn4;->OooO0O0:I

    invoke-static {v0, v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    iget-object v2, v9, Llyiahf/vczjk/yp9;->OooOO0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    invoke-virtual {v2}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;->getIsDisableDOL()Z

    move-result v2

    if-nez v2, :cond_4

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/zx6;->OooO0Oo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v2

    if-eqz v2, :cond_3

    sget-object v2, Llyiahf/vczjk/by6;->OooOOO0:Llyiahf/vczjk/by6;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/by6;->OooO0OO(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v2

    if-nez v2, :cond_4

    :cond_3
    invoke-virtual {v9}, Llyiahf/vczjk/sd9;->OooO0oO()Lgithub/tornaco/android/thanos/core/Logger;

    move-result-object v2

    const-string v3, "Try to enable this app."

    invoke-virtual {v2, v3}, Lgithub/tornaco/android/thanos/core/Logger;->w(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v9, v0, v5}, Llyiahf/vczjk/yp9;->freezePkgs(Ljava/util/List;Z)V

    :cond_4
    :goto_1
    return-object v8

    :pswitch_1
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/i48;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v9, Llyiahf/vczjk/i48;->OooO0o:Llyiahf/vczjk/x58;

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    return-object v8

    :pswitch_2
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/h48;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v9, Llyiahf/vczjk/h48;->OooO0o0:Llyiahf/vczjk/x58;

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    return-object v8

    :pswitch_3
    check-cast v0, Ljava/util/List;

    check-cast v9, Llyiahf/vczjk/yp7;

    invoke-virtual {v9, v5, v5}, Llyiahf/vczjk/fq7;->OooOOo0(II)V

    return-object v8

    :pswitch_4
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/a77;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v8

    :pswitch_5
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/k77;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "keyword"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v0, v9, Llyiahf/vczjk/k77;->OooO:Ljava/lang/String;

    iget-object v0, v9, Llyiahf/vczjk/k77;->OooOO0O:Ljava/util/ArrayList;

    new-instance v2, Llyiahf/vczjk/r07;

    const/4 v3, 0x6

    invoke-direct {v2, v3}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-static {v0, v2}, Llyiahf/vczjk/j21;->Ooooo0o(Ljava/util/List;Llyiahf/vczjk/oe3;)V

    const-wide/16 v2, 0xc8

    invoke-virtual {v9, v2, v3}, Llyiahf/vczjk/k77;->OooOO0o(J)Llyiahf/vczjk/r09;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v8

    :pswitch_6
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/gw6;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v9, Llyiahf/vczjk/gw6;->OooO0o0:Llyiahf/vczjk/x58;

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    return-object v8

    :pswitch_7
    check-cast v0, Llyiahf/vczjk/z8a;

    check-cast v9, Llyiahf/vczjk/rs0;

    invoke-interface {v9, v0}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v8

    :pswitch_8
    check-cast v0, Llyiahf/vczjk/k41;

    iget-object v0, v0, Llyiahf/vczjk/k41;->OooO0o0:Llyiahf/vczjk/r25;

    if-eqz v0, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    goto :goto_2

    :cond_5
    move-object v0, v6

    :goto_2
    instance-of v0, v0, Llyiahf/vczjk/o25;

    check-cast v9, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    iget-object v2, v9, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->Oooo0oO:Llyiahf/vczjk/lm5;

    if-eqz v2, :cond_6

    iget-object v2, v2, Llyiahf/vczjk/lm5;->OooOOOo:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    invoke-virtual {v2, v0}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setRefreshing(Z)V

    return-object v8

    :cond_6
    const-string v0, "binding"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v6

    :pswitch_9
    check-cast v0, Llyiahf/vczjk/dv3;

    sget v2, Llyiahf/vczjk/yu3;->OooO00o:I

    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-interface {v9, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v8

    :pswitch_a
    check-cast v0, Llyiahf/vczjk/nm3;

    check-cast v9, Llyiahf/vczjk/u93;

    iget-object v2, v9, Llyiahf/vczjk/u93;->OooO0Oo:Llyiahf/vczjk/fk7;

    if-nez v2, :cond_7

    goto :goto_3

    :cond_7
    iget-object v2, v2, Llyiahf/vczjk/fk7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Landroidx/slidingpanelayout/widget/SlidingPaneLayout;

    iput-object v0, v2, Landroidx/slidingpanelayout/widget/SlidingPaneLayout;->Oooo00O:Llyiahf/vczjk/nm3;

    new-instance v0, Landroidx/transition/ChangeBounds;

    invoke-direct {v0}, Landroidx/transition/ChangeBounds;-><init>()V

    const-wide/16 v3, 0x12c

    iput-wide v3, v0, Landroidx/transition/Transition;->OooOOOO:J

    new-instance v3, Landroid/view/animation/PathInterpolator;

    const/4 v4, 0x0

    const/high16 v5, 0x3f800000    # 1.0f

    const v6, 0x3e4ccccd    # 0.2f

    invoke-direct {v3, v6, v4, v4, v5}, Landroid/view/animation/PathInterpolator;-><init>(FFFF)V

    iput-object v3, v0, Landroidx/transition/Transition;->OooOOOo:Landroid/animation/TimeInterpolator;

    invoke-static {v2, v0}, Llyiahf/vczjk/rz9;->OooO00o(Landroid/view/ViewGroup;Landroidx/transition/Transition;)V

    invoke-virtual {v2}, Landroid/view/View;->requestLayout()V

    move-object v6, v8

    :goto_3
    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v6, v0, :cond_8

    move-object v8, v6

    :cond_8
    return-object v8

    :pswitch_b
    check-cast v0, Llyiahf/vczjk/z8a;

    check-cast v9, Llyiahf/vczjk/jz1;

    iget-object v0, v9, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v0}, Llyiahf/vczjk/oO0OOo0o;->Oooo00O()Llyiahf/vczjk/n29;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/f13;

    if-nez v0, :cond_9

    invoke-static {v9, v4, v2}, Llyiahf/vczjk/jz1;->OooO0o0(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v0, v2, :cond_9

    move-object v8, v0

    :cond_9
    return-object v8

    :pswitch_c
    check-cast v9, Llyiahf/vczjk/p29;

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-interface {v3, v0, v2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v0, v2, :cond_a

    move-object v8, v0

    :cond_a
    return-object v8

    :pswitch_d
    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    check-cast v9, Landroidx/activity/ComponentActivity;

    const-string v2, "thanoxEdgeToEdge"

    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    new-instance v2, Llyiahf/vczjk/qe1;

    invoke-direct {v2, v0, v5}, Llyiahf/vczjk/qe1;-><init>(ZI)V

    new-instance v3, Llyiahf/vczjk/fd9;

    invoke-direct {v3, v5, v5, v2}, Llyiahf/vczjk/fd9;-><init>(IILlyiahf/vczjk/oe3;)V

    sget v2, Llyiahf/vczjk/qq9;->OooO00o:I

    sget v5, Llyiahf/vczjk/qq9;->OooO0O0:I

    new-instance v6, Llyiahf/vczjk/qe1;

    invoke-direct {v6, v0, v4}, Llyiahf/vczjk/qe1;-><init>(ZI)V

    new-instance v0, Llyiahf/vczjk/fd9;

    invoke-direct {v0, v2, v5, v6}, Llyiahf/vczjk/fd9;-><init>(IILlyiahf/vczjk/oe3;)V

    invoke-static {v9, v3, v0}, Llyiahf/vczjk/ok2;->OooO00o(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    return-object v8

    :catchall_0
    move-exception v0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0

    :pswitch_e
    move-object v2, v0

    check-cast v2, Ljava/lang/String;

    move-object v4, v9

    check-cast v4, Llyiahf/vczjk/t81;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_b
    iget-object v0, v4, Llyiahf/vczjk/t81;->OooO0o0:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v5, v3

    check-cast v5, Ljava/lang/String;

    invoke-virtual {v0, v3, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_b

    return-object v8

    :pswitch_f
    check-cast v0, Ljava/lang/String;

    move-object v2, v9

    check-cast v2, Llyiahf/vczjk/g70;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v2, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v3, v3, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/sc9;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/rs5;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/rs5;

    check-cast v3, Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/yu;

    const-string v3, "$this$updateState"

    invoke-static {v9, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v18, 0x0

    const/16 v22, 0xdff

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v19, v0

    invoke-static/range {v9 .. v22}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v0

    move-object/from16 v3, v19

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4, v0}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    iget-object v0, v2, Llyiahf/vczjk/g70;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_c

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/v74;

    invoke-interface {v5, v6}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    goto :goto_4

    :cond_c
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    invoke-static {v2}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/c70;

    invoke-direct {v5, v2, v3, v6}, Llyiahf/vczjk/c70;-><init>(Llyiahf/vczjk/g70;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {v4, v6, v6, v5, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v8

    :pswitch_10
    check-cast v0, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/i40;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v9, Llyiahf/vczjk/i40;->OooO0o0:Llyiahf/vczjk/x58;

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    return-object v8

    :pswitch_11
    check-cast v0, Llyiahf/vczjk/z8a;

    check-cast v9, Llyiahf/vczjk/l04;

    check-cast v9, Llyiahf/vczjk/p04;

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x22

    if-lt v0, v2, :cond_d

    invoke-virtual {v9}, Llyiahf/vczjk/p04;->OooO00o()Landroid/view/inputmethod/InputMethodManager;

    move-result-object v0

    iget-object v2, v9, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    invoke-static {v0, v2}, Llyiahf/vczjk/oo0OOoo;->OooOOoo(Landroid/view/inputmethod/InputMethodManager;Landroid/view/View;)V

    goto :goto_5

    :cond_d
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :goto_5
    return-object v8

    :pswitch_data_0
    .packed-switch 0x0
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
