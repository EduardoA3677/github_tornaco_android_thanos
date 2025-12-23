.class public final synthetic Llyiahf/vczjk/p35;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/p35;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 21

    const/4 v0, 0x0

    const/4 v1, 0x0

    move-object/from16 v2, p0

    iget v3, v2, Llyiahf/vczjk/p35;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    new-instance v3, Llyiahf/vczjk/g99;

    sget-object v4, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    const/4 v0, 0x1

    invoke-direct {v3, v0, v1, v4, v4}, Llyiahf/vczjk/g99;-><init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V

    return-object v3

    :pswitch_0
    sget v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/StatsActivity;->OoooO0O:I

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    invoke-static {}, Ltornaco/app/thanox/lite/service/api/ShizukuServiceStub;->OooO0o()Llyiahf/vczjk/yp9;

    move-result-object v0

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/nm8;

    invoke-direct {v0}, Llyiahf/vczjk/nm8;-><init>()V

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/al8;

    invoke-direct {v0}, Llyiahf/vczjk/al8;-><init>()V

    return-object v0

    :pswitch_4
    new-instance v3, Llyiahf/vczjk/mi8;

    sget-object v16, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/16 v17, 0x0

    const/16 v20, 0x0

    const/4 v4, 0x0

    const-string v5, "N/A"

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    move-object v6, v5

    invoke-direct/range {v3 .. v20}, Llyiahf/vczjk/mi8;-><init>(ZLjava/lang/String;Ljava/lang/String;ZZZZZZZZLgithub/tornaco/android/thanos/core/profile/ConfigTemplate;Ljava/util/List;ZZZZ)V

    return-object v3

    :pswitch_5
    sget-object v0, Llyiahf/vczjk/ni8;->OooO00o:Llyiahf/vczjk/ni8;

    return-object v0

    :pswitch_6
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No props."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_7
    new-instance v0, Llyiahf/vczjk/hu;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0

    :pswitch_8
    new-instance v0, Llyiahf/vczjk/ut7;

    invoke-direct {v0}, Llyiahf/vczjk/ut7;-><init>()V

    return-object v0

    :pswitch_9
    new-instance v0, Llyiahf/vczjk/nk3;

    invoke-direct {v0}, Llyiahf/vczjk/nk3;-><init>()V

    return-object v0

    :pswitch_a
    const-string v0, "ProfileRuleAndroidHandler"

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/HandlerUtils;->newHandlerOfNewThread(Ljava/lang/String;)Landroid/os/Handler;

    move-result-object v0

    return-object v0

    :pswitch_b
    new-instance v3, Llyiahf/vczjk/s67;

    sget-object v5, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v8, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    sget-object v10, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    sget-object v0, Llyiahf/vczjk/pw;->OooO00o:Llyiahf/vczjk/mw;

    filled-new-array {v10, v0}, [Llyiahf/vczjk/mw;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v11

    const/4 v12, 0x1

    const/4 v13, 0x1

    const/4 v4, 0x0

    move-object v6, v5

    move-object v7, v5

    move-object v9, v8

    invoke-direct/range {v3 .. v13}, Llyiahf/vczjk/s67;-><init>(ZLjava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/Map;Ljava/util/Map;Llyiahf/vczjk/mw;Ljava/util/List;ZZ)V

    return-object v3

    :pswitch_c
    const-string v0, "sensorOffHandler"

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/HandlerUtils;->newHandlerOfNewThread(Ljava/lang/String;)Landroid/os/Handler;

    move-result-object v0

    return-object v0

    :pswitch_d
    sget v0, Lnow/fortuitous/thanos/main/PrebuiltFeatureShortcutActivity;->OooOOO0:I

    return-object v1

    :pswitch_e
    const-string v0, "DelayHandler-PMS#screenOffFreezer"

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/HandlerUtils;->newHandlerOfNewThread(Ljava/lang/String;)Landroid/os/Handler;

    move-result-object v0

    return-object v0

    :pswitch_f
    invoke-static {}, Llyiahf/vczjk/ue6;->OooOo0()Lcom/android/internal/app/IAppOpsService;

    move-result-object v0

    return-object v0

    :pswitch_10
    new-instance v1, Llyiahf/vczjk/ok3;

    invoke-direct {v1}, Llyiahf/vczjk/ok3;-><init>()V

    new-instance v3, Llyiahf/vczjk/k87;

    invoke-direct {v3}, Llyiahf/vczjk/k87;-><init>()V

    iget-object v4, v1, Llyiahf/vczjk/ok3;->OooO0o0:Ljava/util/ArrayList;

    const-class v5, Lgithub/tornaco/thanos/android/module/profile/repo/Profile;

    invoke-static {v5}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object v5

    invoke-virtual {v5}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v6

    invoke-virtual {v5}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    move-result-object v7

    if-ne v6, v7, :cond_0

    const/4 v0, 0x1

    :cond_0
    new-instance v6, Llyiahf/vczjk/f0a;

    invoke-direct {v6, v3, v5, v0}, Llyiahf/vczjk/f0a;-><init>(Llyiahf/vczjk/k87;Lcom/google/gson/reflect/TypeToken;Z)V

    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v1}, Llyiahf/vczjk/ok3;->OooO00o()Llyiahf/vczjk/nk3;

    move-result-object v0

    return-object v0

    :pswitch_11
    new-instance v0, Llyiahf/vczjk/nk3;

    invoke-direct {v0}, Llyiahf/vczjk/nk3;-><init>()V

    return-object v0

    :pswitch_12
    sget v0, Llyiahf/vczjk/hx5;->OooO00o:F

    sget-object v0, Llyiahf/vczjk/z22;->OooO00o:Llyiahf/vczjk/z22;

    return-object v0

    :pswitch_13
    new-instance v0, Llyiahf/vczjk/sw7;

    const/16 v1, 0x13

    invoke-direct {v0, v1}, Llyiahf/vczjk/sw7;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/rt3;

    const/16 v3, 0xb

    invoke-direct {v1, v3}, Llyiahf/vczjk/rt3;-><init>(I)V

    sget-object v3, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v4, Llyiahf/vczjk/lu5;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v3

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/sw7;->OooO0o0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v0}, Llyiahf/vczjk/sw7;->OooO0o()Llyiahf/vczjk/a0;

    move-result-object v0

    return-object v0

    :pswitch_14
    new-instance v0, Llyiahf/vczjk/i68;

    invoke-direct {v0}, Llyiahf/vczjk/i68;-><init>()V

    return-object v0

    :pswitch_15
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v0

    return-object v0

    :pswitch_16
    sget-object v0, Llyiahf/vczjk/xo5;->OooO00o:Llyiahf/vczjk/xo5;

    return-object v0

    :pswitch_17
    sget-object v0, Llyiahf/vczjk/we5;->OooO00o:Llyiahf/vczjk/l39;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_18
    sget-object v0, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    return-object v1

    :pswitch_19
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No LocalSimpleStorageHelper"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_1a
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "CompositionLocal LocalSavedStateRegistryOwner not present"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_1b
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "CompositionLocal LocalLifecycleOwner not present"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_1c
    sget-object v0, Llyiahf/vczjk/q35;->OooO00o:Llyiahf/vczjk/l39;

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
