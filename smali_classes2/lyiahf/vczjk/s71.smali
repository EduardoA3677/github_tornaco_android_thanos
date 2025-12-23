.class public final Llyiahf/vczjk/s71;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $viewModel:Llyiahf/vczjk/t81;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t81;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s71;->$viewModel:Llyiahf/vczjk/t81;

    iput-object p2, p0, Llyiahf/vczjk/s71;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/s71;

    iget-object v0, p0, Llyiahf/vczjk/s71;->$viewModel:Llyiahf/vczjk/t81;

    iget-object v1, p0, Llyiahf/vczjk/s71;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/s71;-><init>(Llyiahf/vczjk/t81;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/s71;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s71;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s71;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/s71;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/s71;->$viewModel:Llyiahf/vczjk/t81;

    iget-object v0, p0, Llyiahf/vczjk/s71;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "appInfo"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    iget-object v1, p1, Llyiahf/vczjk/t81;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
