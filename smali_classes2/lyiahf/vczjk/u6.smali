.class public final Llyiahf/vczjk/u6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/w6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/u6;

    iget-object v0, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/u6;-><init>(Llyiahf/vczjk/w6;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/u6;->label:I

    if-nez v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    iget-object p1, p1, Llyiahf/vczjk/w6;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    iget-object v0, v0, Llyiahf/vczjk/w6;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v0, v0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t6;

    iget-object v0, v0, Llyiahf/vczjk/t6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    invoke-virtual {p1, v0}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLaunchOtherAppAllowListOrNull(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ljava/util/List;

    move-result-object p1

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v3, v0, Llyiahf/vczjk/w6;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v3

    invoke-virtual {v3, v2}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_2
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/u6;->this$0:Llyiahf/vczjk/w6;

    iget-object p1, p1, Llyiahf/vczjk/w6;->OooO0o:Llyiahf/vczjk/s29;

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/t6;

    const/4 v3, 0x1

    const/4 v4, 0x0

    invoke-static {v2, v4, v1, v3}, Llyiahf/vczjk/t6;->OooO00o(Llyiahf/vczjk/t6;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/util/List;I)Llyiahf/vczjk/t6;

    move-result-object v2

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
