.class public final Llyiahf/vczjk/im8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/im8;

    const/4 v0, 0x2

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/im8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/im8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/im8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/im8;->label:I

    const/4 v2, 0x1

    const/4 v3, 0x2

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_6

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_2
    :try_start_0
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0OO()I

    move-result p1

    new-instance v1, Ljava/lang/Integer;

    invoke-direct {v1, p1}, Ljava/lang/Integer;-><init>(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v1

    :goto_0
    instance-of p1, v1, Llyiahf/vczjk/ts7;

    const/4 v4, 0x0

    if-eqz p1, :cond_3

    move-object v1, v4

    :cond_3
    check-cast v1, Ljava/lang/Integer;

    if-nez v1, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    if-eqz p1, :cond_5

    :goto_1
    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput v2, p0, Llyiahf/vczjk/im8;->label:I

    const-wide/16 v4, 0x1f4

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto/16 :goto_5

    :cond_5
    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-eqz p1, :cond_7

    sget-object v1, Llyiahf/vczjk/km8;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    :try_start_1
    new-instance v5, Llyiahf/vczjk/jm8;

    invoke-direct {v5}, Lgithub/tornaco/android/thanos/core/IPkgChangeListener$Stub;-><init>()V

    invoke-interface {p1, v5}, Lgithub/tornaco/android/thanos/core/IThanosLite;->registerPkgStateChangeListener(Lgithub/tornaco/android/thanos/core/IPkgChangeListener;)V

    invoke-interface {p1, v5}, Lgithub/tornaco/android/thanos/core/IThanosLite;->unregisterPkgStateChangeListener(Lgithub/tornaco/android/thanos/core/IPkgChangeListener;)V

    const-string v5, "Test service ok."

    invoke-virtual {v1, v5}, Lgithub/tornaco/android/thanos/core/Logger;->i(Ljava/lang/Object;)V

    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_2

    :catchall_1
    move-exception v5

    invoke-static {v5}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v5

    :goto_2
    invoke-static {v5}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v6

    if-nez v6, :cond_6

    goto :goto_3

    :cond_6
    const-string v5, "testService error"

    invoke-virtual {v1, v6, v5}, Lgithub/tornaco/android/thanos/core/Logger;->e(Ljava/lang/Throwable;Ljava/lang/Object;)V

    sget-object v5, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_3
    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_7

    goto :goto_7

    :cond_7
    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    if-eqz p1, :cond_8

    invoke-interface {p1}, Landroid/os/IBinder;->pingBinder()Z

    move-result p1

    if-eqz p1, :cond_8

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :try_start_2
    iget-object p1, p1, Llyiahf/vczjk/nm8;->OooO0Oo:Llyiahf/vczjk/yw;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o0()Llyiahf/vczjk/jt3;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v5, Landroid/os/Bundle;

    invoke-direct {v5}, Landroid/os/Bundle;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast p1, Landroid/content/ComponentName;

    const-string v6, "shizuku:user-service-arg-component"

    invoke-virtual {v5, v6, p1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    const-string p1, "shizuku:user-service-remove"

    invoke-virtual {v5, p1, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    check-cast v1, Llyiahf/vczjk/ht3;

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/ht3;->OooO0oo(Llyiahf/vczjk/om8;Landroid/os/Bundle;)I
    :try_end_3
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    goto :goto_4

    :catch_0
    move-exception p1

    :try_start_4
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    :cond_8
    :goto_4
    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/nm8;->OooO00o()V

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    iput v3, p0, Llyiahf/vczjk/im8;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/nm8;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_9

    :goto_5
    return-object v0

    :cond_9
    :goto_6
    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-eqz p1, :cond_a

    :goto_7
    return-object p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Unable to get Shizuku user service"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
