.class public final Llyiahf/vczjk/my7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $service:Ltornaco/apps/thanox/running/RunningService;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ny7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ny7;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/my7;->this$0:Llyiahf/vczjk/ny7;

    iput-object p2, p0, Llyiahf/vczjk/my7;->$service:Ltornaco/apps/thanox/running/RunningService;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/my7;

    iget-object v0, p0, Llyiahf/vczjk/my7;->this$0:Llyiahf/vczjk/ny7;

    iget-object v1, p0, Llyiahf/vczjk/my7;->$service:Ltornaco/apps/thanox/running/RunningService;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/my7;-><init>(Llyiahf/vczjk/ny7;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/my7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/my7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/my7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/my7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput v2, p0, Llyiahf/vczjk/my7;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;

    new-instance v0, Landroid/content/Intent;

    invoke-direct {v0}, Landroid/content/Intent;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/my7;->$service:Ltornaco/apps/thanox/running/RunningService;

    iget-object v3, v1, Ltornaco/apps/thanox/running/RunningService;->OooOOO0:Landroid/app/ActivityManager$RunningServiceInfo;

    iget-object v3, v3, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    invoke-virtual {v0, v3}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    iget-object v1, v1, Ltornaco/apps/thanox/running/RunningService;->OooOOO0:Landroid/app/ActivityManager$RunningServiceInfo;

    iget v1, v1, Landroid/app/ActivityManager$RunningServiceInfo;->uid:I

    const-string v3, "uid"

    invoke-virtual {v0, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    invoke-interface {p1, v0}, Lgithub/tornaco/android/thanos/core/IThanosLite;->stopService(Landroid/content/Intent;)Z

    iget-object p1, p0, Llyiahf/vczjk/my7;->this$0:Llyiahf/vczjk/ny7;

    iput-boolean v2, p1, Llyiahf/vczjk/ny7;->OooO:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
