.class public final Llyiahf/vczjk/at;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $listener:Llyiahf/vczjk/vs;

.field final synthetic $pickedFileOS:Ljava/io/OutputStream;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/io/OutputStream;Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/at;->$context:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/at;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p3, p0, Llyiahf/vczjk/at;->$pickedFileOS:Ljava/io/OutputStream;

    iput-object p4, p0, Llyiahf/vczjk/at;->$listener:Llyiahf/vczjk/vs;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/at;

    iget-object v1, p0, Llyiahf/vczjk/at;->$context:Landroid/content/Context;

    iget-object v2, p0, Llyiahf/vczjk/at;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v3, p0, Llyiahf/vczjk/at;->$pickedFileOS:Ljava/io/OutputStream;

    iget-object v4, p0, Llyiahf/vczjk/at;->$listener:Llyiahf/vczjk/vs;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/at;-><init>(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/io/OutputStream;Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/at;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/at;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/at;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/at;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/at;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x2

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_5

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

    goto/16 :goto_1

    :catchall_0
    move-exception p1

    goto/16 :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/at;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/at;->$context:Landroid/content/Context;

    iget-object v1, p0, Llyiahf/vczjk/at;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v6, p0, Llyiahf/vczjk/at;->$pickedFileOS:Ljava/io/OutputStream;

    iget-object v7, p0, Llyiahf/vczjk/at;->$listener:Llyiahf/vczjk/vs;

    :try_start_1
    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object p1

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v1

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAllDisabledComponentsForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ljava/util/List;

    move-result-object p1

    const-string v1, "getAllDisabledComponentsForPackage(...)"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v8, 0xa

    invoke-static {p1, v8}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v8

    invoke-direct {v1, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/content/ComponentName;

    invoke-virtual {v8}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    new-instance p1, Lnow/fortuitous/thanos/apps/AppComponentBackup;

    invoke-direct {p1, v1}, Lnow/fortuitous/thanos/apps/AppComponentBackup;-><init>(Ljava/util/List;)V

    invoke-static {p1}, Lutil/JsonFormatter;->toPrettyJson(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-virtual {p1, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object p1

    const-string v1, "getBytes(...)"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v6, p1}, Ljava/io/OutputStream;->write([B)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :try_start_3
    invoke-interface {v6}, Ljava/io/Closeable;->close()V

    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v1, Llyiahf/vczjk/ys;

    invoke-direct {v1, v7, v5}, Llyiahf/vczjk/ys;-><init>(Llyiahf/vczjk/vs;Llyiahf/vczjk/yo1;)V

    iput v4, p0, Llyiahf/vczjk/at;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    if-ne p1, v0, :cond_4

    goto :goto_4

    :cond_4
    :goto_1
    move-object p1, v2

    goto :goto_3

    :catchall_1
    move-exception p1

    :try_start_4
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception v1

    :try_start_5
    invoke-static {v6, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    :goto_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_3
    iget-object v1, p0, Llyiahf/vczjk/at;->$listener:Llyiahf/vczjk/vs;

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v4

    if-eqz v4, :cond_5

    const/4 v6, 0x0

    new-array v6, v6, [Ljava/lang/Object;

    const-string v7, "performComponentsBackup error"

    invoke-static {v7, v6, v4}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    sget-object v6, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v6, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v7, Llyiahf/vczjk/zs;

    invoke-direct {v7, v1, v4, v5}, Llyiahf/vczjk/zs;-><init>(Llyiahf/vczjk/vs;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/at;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/at;->label:I

    invoke-static {v6, v7, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_4
    return-object v0

    :cond_5
    :goto_5
    return-object v2
.end method
