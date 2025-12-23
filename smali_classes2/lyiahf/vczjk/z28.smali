.class public final Llyiahf/vczjk/z28;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $appLabel:Ljava/lang/String;

.field final synthetic $versionCode:I

.field final synthetic $versionName:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z28;->this$0:Llyiahf/vczjk/i48;

    iput-object p2, p0, Llyiahf/vczjk/z28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p3, p0, Llyiahf/vczjk/z28;->$appLabel:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/z28;->$versionName:Ljava/lang/String;

    iput p5, p0, Llyiahf/vczjk/z28;->$versionCode:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/z28;

    iget-object v1, p0, Llyiahf/vczjk/z28;->this$0:Llyiahf/vczjk/i48;

    iget-object v2, p0, Llyiahf/vczjk/z28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v3, p0, Llyiahf/vczjk/z28;->$appLabel:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/z28;->$versionName:Ljava/lang/String;

    iget v5, p0, Llyiahf/vczjk/z28;->$versionCode:I

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/z28;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/z28;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z28;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/z28;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/z28;->label:I

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

    new-instance v3, Llyiahf/vczjk/y28;

    iget-object v4, p0, Llyiahf/vczjk/z28;->this$0:Llyiahf/vczjk/i48;

    iget-object v5, p0, Llyiahf/vczjk/z28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v6, p0, Llyiahf/vczjk/z28;->$appLabel:Ljava/lang/String;

    iget-object v7, p0, Llyiahf/vczjk/z28;->$versionName:Ljava/lang/String;

    iget v8, p0, Llyiahf/vczjk/z28;->$versionCode:I

    const/4 v9, 0x0

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/y28;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/z28;->label:I

    invoke-static {p1, v3, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
