.class public final Llyiahf/vczjk/jv;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $viewModel:Llyiahf/vczjk/aw;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jv;->$viewModel:Llyiahf/vczjk/aw;

    iput-object p2, p0, Llyiahf/vczjk/jv;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/jv;

    iget-object v0, p0, Llyiahf/vczjk/jv;->$viewModel:Llyiahf/vczjk/aw;

    iget-object v1, p0, Llyiahf/vczjk/jv;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/jv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/jv;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jv;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/jv;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/jv;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/jv;->$viewModel:Llyiahf/vczjk/aw;

    iget-object v0, p0, Llyiahf/vczjk/jv;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/aw;->OooO0o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
