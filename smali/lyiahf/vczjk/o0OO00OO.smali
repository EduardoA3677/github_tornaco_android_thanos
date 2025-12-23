.class public final synthetic Llyiahf/vczjk/o0OO00OO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/a91;I)V
    .locals 0

    const/16 p4, 0x8

    iput p4, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    sget-object p4, Llyiahf/vczjk/ya1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;I)V
    .locals 0

    const/4 p4, 0x6

    iput p4, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    const/16 v0, 0x187

    const/4 v1, 0x1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v3, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOo:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/o0OO00OO;->OooOOOO:Ljava/lang/Object;

    iget v6, p0, Llyiahf/vczjk/o0OO00OO;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    check-cast p2, Ljava/lang/String;

    const-string v0, "id"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p1, :cond_1

    const-string v0, "Delete"

    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    check-cast v5, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object p2

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->deleteConfigTemplate(Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;)Z

    goto :goto_0

    :cond_0
    new-instance p2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;-><init>()V

    const/4 v0, 0x0

    invoke-virtual {p2, v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setSelected(Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getDummyPackageName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p2, v5}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setPkgName(Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setAppLabel(Ljava/lang/String;)V

    invoke-virtual {p2, v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setDummy(Z)V

    const/4 p1, -0x1

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setVersionCode(I)V

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setVersionCode(I)V

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setUid(I)V

    invoke-virtual {p2, v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setUserId(I)V

    check-cast v4, Landroid/content/Context;

    invoke-static {v4, p2}, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OooOoo(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    :goto_0
    check-cast v3, Llyiahf/vczjk/dj8;

    invoke-virtual {v3}, Llyiahf/vczjk/dj8;->OooO()V

    :cond_1
    return-object v2

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v5, Llyiahf/vczjk/kl5;

    check-cast v4, Llyiahf/vczjk/gp3;

    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/er8;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/gp3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Ltornaco/apps/thanox/running/RunningService;

    check-cast v3, Llyiahf/vczjk/ny7;

    check-cast v5, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/ht6;->OooO0oo(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Lnow/fortuitous/thanos/process/v2/RunningProcessState;

    check-cast v3, Llyiahf/vczjk/oy7;

    check-cast v5, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/mt6;->OooO0oo(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Ltornaco/apps/thanox/running/RunningProcessState;

    check-cast v3, Llyiahf/vczjk/ny7;

    check-cast v5, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/ht6;->OooO0oO(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x7

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Ltornaco/apps/thanox/running/RunningService;

    check-cast v3, Llyiahf/vczjk/ny7;

    check-cast v5, Llyiahf/vczjk/qs5;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/ht6;->OooO0o0(Llyiahf/vczjk/qs5;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_5
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Lnow/fortuitous/thanos/process/v2/RunningService;

    check-cast v3, Llyiahf/vczjk/oy7;

    check-cast v5, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/mt6;->OooO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Ljava/lang/String;

    check-cast v4, Llyiahf/vczjk/oe3;

    check-cast v5, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-static {v5, v3, v4, p1, p2}, Llyiahf/vczjk/vt6;->OooOO0O(Ltornaco/apps/thanox/running/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/a91;

    check-cast v5, Llyiahf/vczjk/kl5;

    check-cast v4, Llyiahf/vczjk/yi3;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/jp8;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/yi3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_8
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Float;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/vv5;

    check-cast v4, Llyiahf/vczjk/xc8;

    check-cast v3, Llyiahf/vczjk/ku5;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v4, v3, v0}, Llyiahf/vczjk/vv5;-><init>(FLlyiahf/vczjk/xc8;Llyiahf/vczjk/ku5;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    check-cast v5, Llyiahf/vczjk/xr1;

    invoke-static {v5, v0, v0, p2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v2

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p2, 0xdb1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/a91;

    sget-object v0, Llyiahf/vczjk/ya1;->OooO00o:Llyiahf/vczjk/a91;

    check-cast v5, Llyiahf/vczjk/kl5;

    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/ng0;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p2, 0x181

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v5, Llyiahf/vczjk/ku5;

    check-cast v3, Llyiahf/vczjk/a91;

    check-cast v4, Llyiahf/vczjk/r58;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/nqa;->OooO0Oo(Llyiahf/vczjk/ku5;Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_b
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v5, Llyiahf/vczjk/le3;

    check-cast v4, Llyiahf/vczjk/le3;

    check-cast v3, Llyiahf/vczjk/le3;

    invoke-static {v3, v5, v4, p1, p2}, Llyiahf/vczjk/ng0;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_c
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Llyiahf/vczjk/oe3;

    check-cast v3, Llyiahf/vczjk/ze3;

    check-cast v5, Ljava/util/List;

    invoke-static {p2, v5, p1, v4, v3}, Llyiahf/vczjk/bua;->OooO00o(ILjava/util/List;Llyiahf/vczjk/rf1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    return-object v2

    :pswitch_d
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Llyiahf/vczjk/k02;

    check-cast v3, Llyiahf/vczjk/m02;

    check-cast v5, Llyiahf/vczjk/ov5;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/bua;->OooO(Llyiahf/vczjk/ov5;Llyiahf/vczjk/k02;Llyiahf/vczjk/m02;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_e
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v5, Llyiahf/vczjk/a91;

    check-cast v3, Llyiahf/vczjk/a91;

    check-cast v4, Llyiahf/vczjk/kl5;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/l50;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_f
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    const/16 p2, 0x201

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v3, Llyiahf/vczjk/xu;

    check-cast v4, Llyiahf/vczjk/oe3;

    check-cast v5, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    invoke-virtual {v5, v3, v4, p1, p2}, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OooOoo(Llyiahf/vczjk/xu;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_10
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Llyiahf/vczjk/oe3;

    check-cast v3, Llyiahf/vczjk/oe3;

    check-cast v5, Llyiahf/vczjk/ww2;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/t51;->OooO00o(Llyiahf/vczjk/ww2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    :pswitch_11
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v4, Llyiahf/vczjk/oe3;

    check-cast v3, Llyiahf/vczjk/le3;

    check-cast v5, Llyiahf/vczjk/uy4;

    invoke-static {v5, v4, v3, p1, p2}, Llyiahf/vczjk/os9;->OooOOO(Llyiahf/vczjk/uy4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v2

    nop

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
