.class public final Llyiahf/vczjk/g40;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $target:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i40;


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/g40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-boolean p2, p0, Llyiahf/vczjk/g40;->$target:Z

    iput-object p3, p0, Llyiahf/vczjk/g40;->this$0:Llyiahf/vczjk/i40;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/g40;

    iget-object v0, p0, Llyiahf/vczjk/g40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-boolean v1, p0, Llyiahf/vczjk/g40;->$target:Z

    iget-object v2, p0, Llyiahf/vczjk/g40;->this$0:Llyiahf/vczjk/i40;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/g40;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/g40;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/g40;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/g40;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/g40;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/g40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/ExtensionsKt;->toAppPkg(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Ltornaco/apps/thanox/core/proto/common/AppPkg;

    move-result-object p1

    iget-boolean v1, p0, Llyiahf/vczjk/g40;->$target:Z

    const/4 v5, 0x0

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/g40;->this$0:Llyiahf/vczjk/i40;

    iget-object v1, v1, Llyiahf/vczjk/i40;->OooO0o:Llyiahf/vczjk/o30;

    iput v4, p0, Llyiahf/vczjk/g40;->label:I

    iget-object v1, v1, Llyiahf/vczjk/o30;->OooO00o:Llyiahf/vczjk/l30;

    iget-object v1, v1, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {v1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/b30;

    invoke-direct {v3, p1, v5}, Llyiahf/vczjk/b30;-><init>(Ltornaco/apps/thanox/core/proto/common/AppPkg;Llyiahf/vczjk/yo1;)V

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_0

    :cond_3
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_4

    goto :goto_1

    :cond_4
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_8

    goto :goto_4

    :cond_5
    iget-object v1, p0, Llyiahf/vczjk/g40;->this$0:Llyiahf/vczjk/i40;

    iget-object v1, v1, Llyiahf/vczjk/i40;->OooO0o:Llyiahf/vczjk/o30;

    iput v3, p0, Llyiahf/vczjk/g40;->label:I

    iget-object v1, v1, Llyiahf/vczjk/o30;->OooO00o:Llyiahf/vczjk/l30;

    iget-object v1, v1, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {v1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/g30;

    invoke-direct {v3, p1, v5}, Llyiahf/vczjk/g30;-><init>(Ltornaco/apps/thanox/core/proto/common/AppPkg;Llyiahf/vczjk/yo1;)V

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    goto :goto_2

    :cond_6
    move-object p1, v2

    :goto_2
    if-ne p1, v0, :cond_7

    goto :goto_3

    :cond_7
    move-object p1, v2

    :goto_3
    if-ne p1, v0, :cond_8

    :goto_4
    return-object v0

    :cond_8
    return-object v2
.end method
