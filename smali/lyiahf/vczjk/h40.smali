.class public final Llyiahf/vczjk/h40;
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

    iput-object p1, p0, Llyiahf/vczjk/h40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-boolean p2, p0, Llyiahf/vczjk/h40;->$target:Z

    iput-object p3, p0, Llyiahf/vczjk/h40;->this$0:Llyiahf/vczjk/i40;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/h40;

    iget-object v0, p0, Llyiahf/vczjk/h40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-boolean v1, p0, Llyiahf/vczjk/h40;->$target:Z

    iget-object v2, p0, Llyiahf/vczjk/h40;->this$0:Llyiahf/vczjk/i40;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/h40;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/h40;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/h40;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h40;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/h40;->label:I

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

    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v1, Llyiahf/vczjk/g40;

    iget-object v3, p0, Llyiahf/vczjk/h40;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-boolean v4, p0, Llyiahf/vczjk/h40;->$target:Z

    iget-object v5, p0, Llyiahf/vczjk/h40;->this$0:Llyiahf/vczjk/i40;

    const/4 v6, 0x0

    invoke-direct {v1, v3, v4, v5, v6}, Llyiahf/vczjk/g40;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/h40;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
