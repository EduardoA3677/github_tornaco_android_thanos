.class public final Llyiahf/vczjk/bv;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/dv;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/bv;

    iget-object v0, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/bv;-><init>(Llyiahf/vczjk/dv;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bv;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bv;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bv;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/bv;->label:I

    if-nez v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    iget-object p1, p1, Llyiahf/vczjk/dv;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    iget-object v0, v0, Llyiahf/vczjk/dv;->OooO0Oo:Llyiahf/vczjk/gh7;

    iget-object v0, v0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xu;

    iget-object v0, v0, Llyiahf/vczjk/xu;->OooO0o0:Llyiahf/vczjk/nw;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/nw;->OooO00o:Ljava/lang/String;

    goto :goto_0

    :cond_0
    const-string v0, "D878029F-1D75-42EF-9DEA-48B552172C3D"

    :goto_0
    invoke-virtual {p1, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getInstalledPkgsByPackageSetId(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_1
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v9, 0x0

    if-eqz v1, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v2, v0, Llyiahf/vczjk/dv;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    iget-object v4, v0, Llyiahf/vczjk/dv;->OooO0Oo:Llyiahf/vczjk/gh7;

    iget-object v4, v4, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/xu;

    iget v4, v4, Llyiahf/vczjk/xu;->OooO0OO:I

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v5

    const-string v6, "fromAppInfo(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v4, v5}, Lgithub/tornaco/android/thanos/core/ops/OpsManager;->getPackagePermInfo(ILgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/ops/PermInfo;

    move-result-object v2

    if-eqz v2, :cond_2

    new-instance v9, Llyiahf/vczjk/vt;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {v9, v1, v2}, Llyiahf/vczjk/vt;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Lgithub/tornaco/android/thanos/core/ops/PermInfo;)V

    :cond_2
    if-eqz v9, :cond_1

    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/bv;->this$0:Llyiahf/vczjk/dv;

    iget-object p1, p1, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/xu;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v2, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3c

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/xu;->OooO00o(Llyiahf/vczjk/xu;ZLjava/util/ArrayList;ILjava/lang/String;Llyiahf/vczjk/nw;Ljava/util/List;I)Llyiahf/vczjk/xu;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v9, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
