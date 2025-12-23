.class public final synthetic Llyiahf/vczjk/gu6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/gu6;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/gu6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gu6;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/gu6;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/gu6;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gu6;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/fj9;Llyiahf/vczjk/uy9;Llyiahf/vczjk/qs5;)V
    .locals 0

    const/16 p1, 0xf

    iput p1, p0, Llyiahf/vczjk/gu6;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/gu6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gu6;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    const-string v1, "stop"

    const-string v2, "copy"

    const v3, -0x25b7f321

    const-string v4, "$this$LazyColumn"

    const/4 v5, 0x0

    const-string v6, "it"

    const/4 v7, 0x3

    const/4 v8, 0x1

    const/4 v9, 0x0

    sget-object v10, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v11, v0, Llyiahf/vczjk/gu6;->OooOOO:Ljava/lang/Object;

    iget-object v12, v0, Llyiahf/vczjk/gu6;->OooOOOO:Ljava/lang/Object;

    iget v13, v0, Llyiahf/vczjk/gu6;->OooOOO0:I

    packed-switch v13, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/fv4;

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v2, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;->OoooO0O:I

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/kka;

    iget-object v2, v2, Llyiahf/vczjk/kka;->OooO00o:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v4

    new-instance v5, Llyiahf/vczjk/fma;

    invoke-direct {v5, v2}, Llyiahf/vczjk/fma;-><init>(Ljava/util/List;)V

    new-instance v6, Llyiahf/vczjk/gma;

    check-cast v11, Llyiahf/vczjk/mka;

    invoke-direct {v6, v2, v11}, Llyiahf/vczjk/gma;-><init>(Ljava/util/List;Llyiahf/vczjk/mka;)V

    new-instance v2, Llyiahf/vczjk/a91;

    invoke-direct {v2, v3, v6, v8}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v4, v9, v5, v2}, Llyiahf/vczjk/fv4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    return-object v10

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Lgithub/tornaco/android/thanos/core/power/WakeLockStats;

    check-cast v11, Llyiahf/vczjk/bla;

    invoke-virtual {v11}, Llyiahf/vczjk/bla;->OooOO0()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v2

    iget-object v3, v1, Lgithub/tornaco/android/thanos/core/power/WakeLockStats;->pkg:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v3

    iget-object v4, v1, Lgithub/tornaco/android/thanos/core/power/WakeLockStats;->pkg:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v4

    invoke-virtual {v2, v3, v4}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfoForUser(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v2

    if-eqz v2, :cond_1

    iget-object v1, v1, Lgithub/tornaco/android/thanos/core/power/WakeLockStats;->pkg:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    check-cast v12, Lgithub/tornaco/android/thanos/core/power/PowerManager;

    invoke-virtual {v12, v1, v8}, Lgithub/tornaco/android/thanos/core/power/PowerManager;->getSeenWakeLocksForPkg(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)Ljava/util/List;

    move-result-object v1

    const-string v3, "getSeenWakeLocksForPkg(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v1, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/dla;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->getTag()Ljava/lang/String;

    move-result-object v8

    const-string v6, "getTag(...)"

    invoke-static {v8, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->getFlags()I

    move-result v6

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->getOwnerPackageName()Ljava/lang/String;

    move-result-object v9

    const-string v7, "getOwnerPackageName(...)"

    invoke-static {v9, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->getOwnerUserId()I

    move-result v7

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->isHeld()Z

    move-result v10

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/power/SeenWakeLock;->isBlock()Z

    move-result v11

    invoke-direct/range {v5 .. v11}, Llyiahf/vczjk/dla;-><init>(IILjava/lang/String;Ljava/lang/String;ZZ)V

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    new-instance v9, Llyiahf/vczjk/uh6;

    invoke-direct {v9, v2, v3}, Llyiahf/vczjk/uh6;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/util/ArrayList;)V

    :cond_1
    return-object v9

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/Throwable;

    check-cast v11, Llyiahf/vczjk/zl8;

    invoke-virtual {v11}, Llyiahf/vczjk/zl8;->OooO0o0()Z

    move-result v1

    if-nez v1, :cond_2

    check-cast v12, Llyiahf/vczjk/yo9;

    invoke-virtual {v12}, Llyiahf/vczjk/yo9;->OooO00o()V

    :cond_2
    return-object v10

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/hg2;

    check-cast v12, Llyiahf/vczjk/ki9;

    invoke-virtual {v12}, Llyiahf/vczjk/ki9;->OooO00o()J

    move-result-wide v2

    const/16 v4, 0x3c

    check-cast v11, Llyiahf/vczjk/qqa;

    invoke-static {v1, v11, v2, v3, v4}, Llyiahf/vczjk/zsa;->Oooo0(Llyiahf/vczjk/hg2;Llyiahf/vczjk/qqa;JI)V

    return-object v10

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/tm0;

    iget-object v2, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v2}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v2

    iget-object v4, v1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v4}, Llyiahf/vczjk/qj0;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    check-cast v11, Llyiahf/vczjk/qj8;

    invoke-interface {v11, v2, v3, v4, v1}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/gu6;

    check-cast v12, Llyiahf/vczjk/ki9;

    const/16 v4, 0x11

    invoke-direct {v3, v4, v2, v12}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/sm0;

    invoke-direct {v2, v3}, Llyiahf/vczjk/sm0;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v1

    return-object v1

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/tq8;

    check-cast v11, Llyiahf/vczjk/uy9;

    invoke-virtual {v11}, Llyiahf/vczjk/uy9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    iget-wide v3, v1, Llyiahf/vczjk/tq8;->OooO00o:J

    const/16 v5, 0x20

    shr-long/2addr v3, v5

    long-to-int v3, v3

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    mul-float/2addr v3, v2

    iget-wide v6, v1, Llyiahf/vczjk/tq8;->OooO00o:J

    const-wide v8, 0xffffffffL

    and-long/2addr v6, v8

    long-to-int v1, v6

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    mul-float/2addr v1, v2

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tq8;

    iget-wide v6, v2, Llyiahf/vczjk/tq8;->OooO00o:J

    shr-long/2addr v6, v5

    long-to-int v2, v6

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    cmpg-float v2, v2, v3

    if-nez v2, :cond_3

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/tq8;

    iget-wide v6, v2, Llyiahf/vczjk/tq8;->OooO00o:J

    and-long/2addr v6, v8

    long-to-int v2, v6

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    cmpg-float v2, v2, v1

    if-nez v2, :cond_3

    goto :goto_1

    :cond_3
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v6, v1

    shl-long v1, v2, v5

    and-long v3, v6, v8

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/tq8;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/tq8;-><init>(J)V

    invoke-interface {v12, v3}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :goto_1
    return-object v10

    :pswitch_5
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/zp4;

    const-string v2, "$this$FeatureGrid"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ow5;

    iget-object v2, v2, Llyiahf/vczjk/ow5;->OooO0O0:Ljava/util/List;

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/xw2;

    iget-object v4, v4, Llyiahf/vczjk/xw2;->OooO0O0:Ljava/util/List;

    invoke-static {v4, v3}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v2

    new-instance v4, Llyiahf/vczjk/o99;

    invoke-direct {v4, v3}, Llyiahf/vczjk/o99;-><init>(Ljava/util/ArrayList;)V

    new-instance v5, Llyiahf/vczjk/p99;

    check-cast v11, Llyiahf/vczjk/n07;

    invoke-direct {v5, v3, v11}, Llyiahf/vczjk/p99;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/n07;)V

    new-instance v3, Llyiahf/vczjk/a91;

    const v6, 0x29b3c0fe

    invoke-direct {v3, v6, v5, v8}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v2, v9, v4, v3}, Llyiahf/vczjk/zp4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    return-object v10

    :pswitch_6
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    new-instance v2, Llyiahf/vczjk/fi8;

    check-cast v12, Llyiahf/vczjk/n17;

    invoke-direct {v2, v12, v1, v9}, Llyiahf/vczjk/fi8;-><init>(Llyiahf/vczjk/n17;ZLlyiahf/vczjk/yo1;)V

    check-cast v11, Llyiahf/vczjk/xr1;

    invoke-static {v11, v9, v9, v2, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v10

    :pswitch_7
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kna;

    new-instance v2, Llyiahf/vczjk/bs2;

    check-cast v12, Llyiahf/vczjk/x8a;

    invoke-direct {v2, v12, v1}, Llyiahf/vczjk/bs2;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/kna;)V

    check-cast v11, Llyiahf/vczjk/ys5;

    iget-object v1, v11, Llyiahf/vczjk/ys5;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-object v10

    :pswitch_8
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/ky6;

    invoke-static {v1, v5}, Llyiahf/vczjk/vl6;->OooOoo0(Llyiahf/vczjk/ky6;Z)J

    move-result-wide v2

    const-wide/16 v4, 0x0

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/p86;->OooO0O0(JJ)Z

    move-result v2

    if-nez v2, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/ky6;->OooO00o()V

    :cond_5
    check-cast v11, Llyiahf/vczjk/kb9;

    iget-object v2, v11, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-wide v2, v2, Llyiahf/vczjk/nb9;->Oooo0O0:J

    iget-wide v4, v1, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-static {v4, v5, v2, v3}, Llyiahf/vczjk/er8;->OooOO0O(JJ)Llyiahf/vczjk/xn6;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    check-cast v12, Llyiahf/vczjk/ze3;

    invoke-interface {v12, v2, v1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v10

    :pswitch_9
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/String;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-virtual {v2}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v2

    const-string v3, "getId(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/h48;

    invoke-static {v11}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/r38;

    invoke-direct {v4, v11, v2, v1, v9}, Llyiahf/vczjk/r38;-><init>(Llyiahf/vczjk/h48;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v9, v9, v4, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v10

    :pswitch_a
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_6

    check-cast v11, Llyiahf/vczjk/i48;

    check-cast v12, Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    const-string v1, "set"

    invoke-static {v12, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v11, Llyiahf/vczjk/i48;->OooO0o:Llyiahf/vczjk/x58;

    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v11}, Llyiahf/vczjk/i48;->OooO()V

    :cond_6
    return-object v10

    :pswitch_b
    move-object/from16 v15, p1

    check-cast v15, Ljava/lang/String;

    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v14, v12

    check-cast v14, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v14}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getVersionName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "getVersionName(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v14}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getVersionCode()I

    move-result v17

    move-object v13, v11

    check-cast v13, Llyiahf/vczjk/i48;

    invoke-static {v13}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v2

    new-instance v12, Llyiahf/vczjk/z28;

    const/16 v18, 0x0

    move-object/from16 v16, v1

    invoke-direct/range {v12 .. v18}, Llyiahf/vczjk/z28;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    invoke-static {v2, v9, v9, v12, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v10

    :pswitch_c
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/ah5;

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v3, Llyiahf/vczjk/ah5;->OooO00o:Ljava/lang/String;

    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    check-cast v11, Llyiahf/vczjk/ny7;

    check-cast v12, Ltornaco/apps/thanox/running/RunningService;

    if-eqz v2, :cond_7

    iget-object v1, v12, Ltornaco/apps/thanox/running/RunningService;->OooOOO0:Landroid/app/ActivityManager$RunningServiceInfo;

    iget-object v1, v1, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    invoke-virtual {v1}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v1

    iget-object v2, v11, Llyiahf/vczjk/ny7;->OooO0o0:Landroid/content/Context;

    const-string v3, "Service name"

    invoke-static {v2, v3, v1}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/kh6;->OooOOO0(Landroid/content/Context;)V

    goto :goto_3

    :cond_7
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_8

    invoke-static {v11}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/my7;

    invoke-direct {v2, v11, v12, v9}, Llyiahf/vczjk/my7;-><init>(Llyiahf/vczjk/ny7;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v9, v9, v2, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iget-object v1, v12, Ltornaco/apps/thanox/running/RunningService;->OooOOOo:Llyiahf/vczjk/qs5;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_8
    :goto_3
    return-object v10

    :pswitch_d
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/ah5;

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v3, Llyiahf/vczjk/ah5;->OooO00o:Ljava/lang/String;

    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    check-cast v11, Llyiahf/vczjk/ny7;

    check-cast v12, Ltornaco/apps/thanox/running/RunningProcessState;

    if-eqz v2, :cond_9

    iget-object v1, v12, Ltornaco/apps/thanox/running/RunningProcessState;->OooOOO:Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;

    iget-object v1, v1, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->processName:Ljava/lang/String;

    iget-object v2, v11, Llyiahf/vczjk/ny7;->OooO0o0:Landroid/content/Context;

    const-string v3, "Process name"

    invoke-static {v2, v3, v1}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/kh6;->OooOOO0(Landroid/content/Context;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    invoke-static {v11}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ly7;

    invoke-direct {v2, v12, v11, v9}, Llyiahf/vczjk/ly7;-><init>(Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ny7;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v9, v9, v2, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iget-object v1, v12, Ltornaco/apps/thanox/running/RunningProcessState;->OooOOo0:Llyiahf/vczjk/qs5;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_a
    :goto_4
    return-object v10

    :pswitch_e
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/nw7;

    const-string v2, "rule"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v13, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    check-cast v11, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getId()I

    move-result v14

    invoke-interface {v1}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object v15

    const-string v2, "getName(...)"

    invoke-static {v15, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1}, Llyiahf/vczjk/nw7;->getDescription()Ljava/lang/String;

    move-result-object v2

    const-string v3, "getDescription(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getRawJson()Ljava/lang/String;

    move-result-object v3

    const-string v4, "getRawJson(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getAuthor()Ljava/lang/String;

    move-result-object v4

    const-string v5, "getAuthor(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getLastUpdateTime()J

    move-result-wide v19

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->isEnabled()Z

    move-result v21

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getFormat()I

    move-result v22

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getVersionCode()I

    move-result v23

    invoke-interface {v1}, Llyiahf/vczjk/nw7;->getPriority()I

    move-result v24

    move-object/from16 v16, v2

    move-object/from16 v17, v3

    move-object/from16 v18, v4

    invoke-direct/range {v13 .. v24}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JZIII)V

    invoke-virtual {v13}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->toString()Ljava/lang/String;

    check-cast v12, Llyiahf/vczjk/pb7;

    iget-object v2, v12, Llyiahf/vczjk/pb7;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Ljava/util/LinkedHashMap;

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->getId()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    new-instance v4, Lnow/fortuitous/profile/RuleInfoExt;

    invoke-direct {v4, v13, v1}, Lnow/fortuitous/profile/RuleInfoExt;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Llyiahf/vczjk/nw7;)V

    invoke-interface {v2, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v10

    :pswitch_f
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/String;

    sget v1, Lnow/fortuitous/profile/ProfileService$monitor$1;->OooOO0O:I

    check-cast v12, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {v12}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v11, Lnow/fortuitous/profile/ProfileService;

    iget-boolean v1, v11, Lnow/fortuitous/profile/ProfileService;->OooOO0O:Z

    if-nez v1, :cond_b

    goto :goto_5

    :cond_b
    iget-object v1, v11, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    if-nez v1, :cond_c

    goto :goto_5

    :cond_c
    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "getPkgName(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "github.tornaco.android.thanos"

    invoke-static {v1, v3, v5}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_d

    goto :goto_5

    :cond_d
    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "github.tornaco.android.thanos.shortcut"

    invoke-static {v1, v2, v5}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_e

    goto :goto_5

    :cond_e
    iget-object v1, v11, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    invoke-virtual {v11, v1}, Lnow/fortuitous/profile/ProfileService;->getConfigTemplateById(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    move-result-object v1

    if-nez v1, :cond_f

    iget-object v1, v11, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "setupAutoConfigForNewInstalledAppsIfNeed template with id "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " == null"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_5

    :cond_f
    invoke-virtual {v11, v12, v1}, Lnow/fortuitous/profile/ProfileService;->applyConfigTemplateForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;)Z

    iget-boolean v1, v11, Lnow/fortuitous/profile/ProfileService;->OooOOO:Z

    if-eqz v1, :cond_10

    invoke-virtual {v11, v12}, Lnow/fortuitous/profile/ProfileService;->OooOooo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    :cond_10
    :goto_5
    invoke-virtual {v11}, Lnow/fortuitous/profile/ProfileService;->OooOo0O()Z

    move-result v1

    if-eqz v1, :cond_11

    new-instance v1, Lnow/fortuitous/profile/fact/ThanoxFacts;

    invoke-direct {v1}, Lnow/fortuitous/profile/fact/ThanoxFacts;-><init>()V

    invoke-virtual {v1, v8}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setPkgAdded(Z)V

    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setPkgName(Ljava/lang/String;)V

    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v2}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setUserId(Ljava/lang/Integer;)V

    invoke-virtual {v1}, Lnow/fortuitous/profile/fact/ThanoxFacts;->compose()Llyiahf/vczjk/gv2;

    move-result-object v1

    const-string v2, "onPackageAdded"

    invoke-virtual {v11, v1, v2}, Lnow/fortuitous/profile/ProfileService;->OooOoO(Llyiahf/vczjk/gv2;Ljava/lang/String;)V

    :cond_11
    return-object v10

    :pswitch_10
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/fv4;

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v11, Llyiahf/vczjk/sr2;

    iget-object v2, v11, Llyiahf/vczjk/sr2;->OooO00o:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v4

    new-instance v5, Llyiahf/vczjk/y77;

    invoke-direct {v5, v2}, Llyiahf/vczjk/y77;-><init>(Ljava/util/List;)V

    new-instance v6, Llyiahf/vczjk/z77;

    check-cast v12, Llyiahf/vczjk/oe3;

    invoke-direct {v6, v2, v12}, Llyiahf/vczjk/z77;-><init>(Ljava/util/List;Llyiahf/vczjk/oe3;)V

    new-instance v2, Llyiahf/vczjk/a91;

    invoke-direct {v2, v3, v6, v8}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v1, v4, v9, v5, v2}, Llyiahf/vczjk/fv4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    return-object v10

    :pswitch_11
    move-object/from16 v1, p1

    check-cast v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;

    invoke-direct {v2, v1}, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;)V

    check-cast v12, Landroid/content/Context;

    const-string v1, "context"

    invoke-static {v12, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Landroid/content/Intent;

    const-class v3, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetailsActivity;

    invoke-direct {v1, v12, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v3, "details"

    invoke-virtual {v1, v3, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    check-cast v11, Llyiahf/vczjk/wa5;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/wa5;->OooO00o(Ljava/lang/Object;)V

    return-object v10

    :pswitch_12
    move-object/from16 v1, p1

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v2

    check-cast v11, Llyiahf/vczjk/kw6;

    iget v3, v11, Llyiahf/vczjk/kw6;->OooO0O0:I

    if-ne v2, v3, :cond_12

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v1

    check-cast v12, Ljava/lang/String;

    invoke-static {v12, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_12

    move v5, v8

    :cond_12
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    return-object v1

    :pswitch_13
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/String;

    const-string v2, "pin"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v3, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;->OoooO0O:I

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/su6;

    iget-object v3, v3, Llyiahf/vczjk/su6;->OooO00o:Llyiahf/vczjk/wu6;

    sget-object v4, Llyiahf/vczjk/uu6;->OooO00o:Llyiahf/vczjk/uu6;

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    sget-object v10, Llyiahf/vczjk/vu6;->OooO00o:Llyiahf/vczjk/vu6;

    if-eqz v6, :cond_14

    :cond_13
    move v3, v8

    goto :goto_6

    :cond_14
    invoke-static {v3, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_13

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/su6;

    iget-object v3, v3, Llyiahf/vczjk/su6;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3

    :goto_6
    check-cast v11, Llyiahf/vczjk/pu6;

    iget-object v6, v11, Llyiahf/vczjk/pu6;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v12, v6, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v12, Llyiahf/vczjk/s29;

    invoke-virtual {v12}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/su6;

    iget-object v12, v12, Llyiahf/vczjk/su6;->OooO00o:Llyiahf/vczjk/wu6;

    invoke-static {v12, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    iget-object v14, v11, Llyiahf/vczjk/pu6;->OooO0o:Llyiahf/vczjk/s29;

    if-eqz v13, :cond_16

    :cond_15
    invoke-virtual {v14}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/su6;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v4, Llyiahf/vczjk/su6;

    invoke-direct {v4, v10, v1, v8}, Llyiahf/vczjk/su6;-><init>(Llyiahf/vczjk/wu6;Ljava/lang/String;Z)V

    invoke-virtual {v14, v2, v4}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_15

    goto :goto_7

    :cond_16
    invoke-static {v12, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_19

    iget-object v6, v6, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v6, Llyiahf/vczjk/s29;

    invoke-virtual {v6}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/su6;

    iget-object v6, v6, Llyiahf/vczjk/su6;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_18

    :cond_17
    invoke-virtual {v14}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/su6;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/su6;

    const-string v5, ""

    invoke-direct {v2, v4, v5, v8}, Llyiahf/vczjk/su6;-><init>(Llyiahf/vczjk/wu6;Ljava/lang/String;Z)V

    invoke-virtual {v14, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_17

    invoke-static {v11}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/nu6;

    invoke-direct {v2, v11, v9}, Llyiahf/vczjk/nu6;-><init>(Llyiahf/vczjk/pu6;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v9, v9, v2, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_7

    :cond_18
    invoke-virtual {v14}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/su6;

    sget-object v8, Llyiahf/vczjk/tu6;->OooO00o:Llyiahf/vczjk/tu6;

    iget-object v6, v6, Llyiahf/vczjk/su6;->OooO0O0:Ljava/lang/String;

    invoke-static {v6, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v10, Llyiahf/vczjk/su6;

    invoke-direct {v10, v8, v6, v5}, Llyiahf/vczjk/su6;-><init>(Llyiahf/vczjk/wu6;Ljava/lang/String;Z)V

    invoke-virtual {v14, v4, v10}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_18

    iget-object v2, v11, Llyiahf/vczjk/pu6;->OooO:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v2

    invoke-virtual {v2, v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setLockPin(Ljava/lang/String;)V

    invoke-static {v11}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ou6;

    invoke-direct {v2, v11, v9}, Llyiahf/vczjk/ou6;-><init>(Llyiahf/vczjk/pu6;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v9, v9, v2, v7}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_19
    :goto_7
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
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
