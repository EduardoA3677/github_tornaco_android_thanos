.class public final Llyiahf/vczjk/y28;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $appLabel:Ljava/lang/String;

.field final synthetic $versionCode:I

.field final synthetic $versionName:Ljava/lang/String;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/y28;->this$0:Llyiahf/vczjk/i48;

    iput-object p2, p0, Llyiahf/vczjk/y28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p3, p0, Llyiahf/vczjk/y28;->$appLabel:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/y28;->$versionName:Ljava/lang/String;

    iput p5, p0, Llyiahf/vczjk/y28;->$versionCode:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/y28;

    iget-object v1, p0, Llyiahf/vczjk/y28;->this$0:Llyiahf/vczjk/i48;

    iget-object v2, p0, Llyiahf/vczjk/y28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v3, p0, Llyiahf/vczjk/y28;->$appLabel:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/y28;->$versionName:Ljava/lang/String;

    iget v5, p0, Llyiahf/vczjk/y28;->$versionCode:I

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/y28;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/y28;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/y28;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y28;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/y28;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/y28;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/y28;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/y28;->this$0:Llyiahf/vczjk/i48;

    iget-object v1, p0, Llyiahf/vczjk/y28;->$appInfo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v5, p0, Llyiahf/vczjk/y28;->$appLabel:Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/y28;->$versionName:Ljava/lang/String;

    iget v7, p0, Llyiahf/vczjk/y28;->$versionCode:I

    :try_start_1
    iget-object v8, p1, Llyiahf/vczjk/i48;->OooO0o0:Landroid/content/Context;

    invoke-static {v8, v1, v5, v6, v7}, Llyiahf/vczjk/dl6;->OooO0OO(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;I)Ljava/io/File;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/i48;->OooOO0O:Llyiahf/vczjk/jl8;

    new-instance v5, Llyiahf/vczjk/l79;

    invoke-direct {v5, v1}, Llyiahf/vczjk/l79;-><init>(Ljava/io/File;)V

    iput v4, p0, Llyiahf/vczjk/y28;->label:I

    invoke-virtual {p1, v5, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_3

    goto :goto_3

    :cond_3
    :goto_0
    move-object p1, v2

    goto :goto_2

    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_2
    iget-object v1, p0, Llyiahf/vczjk/y28;->this$0:Llyiahf/vczjk/i48;

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v4

    if-eqz v4, :cond_4

    const/4 v5, 0x0

    new-array v5, v5, [Ljava/lang/Object;

    const-string v6, "createShortcutStubApkFor"

    invoke-static {v6, v5, v4}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    sget-object v5, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v5, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v6, Llyiahf/vczjk/x28;

    const/4 v7, 0x0

    invoke-direct {v6, v1, v4, v7}, Llyiahf/vczjk/x28;-><init>(Llyiahf/vczjk/i48;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/y28;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/y28;->label:I

    invoke-static {v5, v6, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_3
    return-object v0

    :cond_4
    :goto_4
    return-object v2
.end method
