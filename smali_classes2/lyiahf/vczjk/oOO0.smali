.class public final synthetic Llyiahf/vczjk/oOO0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/oOO0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/concurrent/atomic/AtomicBoolean;Llyiahf/vczjk/mo0;Llyiahf/vczjk/le3;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Llyiahf/vczjk/oOO0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/rm4;

    iput-object p3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lnow/fortuitous/app/infinite/OooO00o;Ljava/lang/String;Landroid/os/IInterface;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/oOO0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    const/4 v0, 0x1

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/oOO0;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mo0;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rm4;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mo0;->OooO00o(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mo0;->OooO0O0(Ljava/lang/Throwable;)V

    :goto_0
    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bp8;

    iget-object v0, v0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n77;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/g29;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xo8;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n77;->OooO0o(Llyiahf/vczjk/g29;Llyiahf/vczjk/xo8;)Z

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bx7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getCustomSuCommand()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getCustomSuCommand()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\n"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_pref_summary_rule_engine_custom_su:I

    invoke-virtual {v0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Landroidx/preference/Preference;

    invoke-virtual {v1, v0}, Landroidx/preference/Preference;->OooOo0o(Ljava/lang/CharSequence;)V

    :cond_1
    return-void

    :pswitch_2
    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Landroid/content/Intent;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/mf7;

    iget-object v4, v4, Llyiahf/vczjk/mf7;->OooOO0o:Landroid/os/RemoteCallbackList;

    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->beginBroadcast()I

    move-result v5

    move v6, v1

    :goto_1
    if-ge v6, v5, :cond_3

    :try_start_1
    invoke-virtual {v4, v6}, Landroid/os/RemoteCallbackList;->getBroadcastCookie(I)Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-static {v3, v7}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2

    invoke-virtual {v4, v6}, Landroid/os/RemoteCallbackList;->getBroadcastItem(I)Landroid/os/IInterface;

    move-result-object v7

    check-cast v7, Lgithub/tornaco/android/thanos/core/push/IChannelHandler;

    invoke-interface {v7, v2}, Lgithub/tornaco/android/thanos/core/push/IChannelHandler;->onMessageArrive(Landroid/content/Intent;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_2

    :catchall_1
    move-exception v7

    :try_start_2
    const-string v8, "Error onMessageArrive"

    new-array v9, v1, [Ljava/lang/Object;

    invoke-static {v8, v9, v7}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :cond_2
    :goto_2
    add-int/2addr v6, v0

    goto :goto_1

    :catchall_2
    move-exception v0

    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->finishBroadcast()V

    throw v0

    :cond_3
    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->finishBroadcast()V

    return-void

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/profile/ProfileService;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/gv2;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    :try_start_3
    invoke-virtual {v0, v1, v2}, Lnow/fortuitous/profile/ProfileService;->OooOoOO(Llyiahf/vczjk/gv2;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    goto :goto_3

    :catchall_3
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_3
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_4

    const-string v1, "publishFacts error"

    invoke-static {v1, v0}, Llyiahf/vczjk/l87;->OooO0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_4
    return-void

    :pswitch_4
    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/n77;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qo0;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/wra;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :try_start_4
    iget-object v2, v2, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v2}, Llyiahf/vczjk/o0o0Oo;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0
    :try_end_4
    .catch Ljava/lang/InterruptedException; {:try_start_4 .. :try_end_4} :catch_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_4 .. :try_end_4} :catch_0

    :catch_0
    iget-object v2, v1, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v2

    :try_start_5
    iget-object v4, v3, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    invoke-static {v4}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v4

    iget-object v5, v4, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/n77;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/wra;

    move-result-object v6

    if-ne v6, v3, :cond_5

    invoke-virtual {v1, v5}, Llyiahf/vczjk/n77;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/wra;

    goto :goto_4

    :catchall_4
    move-exception v0

    goto :goto_6

    :cond_5
    :goto_4
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    new-instance v7, Ljava/lang/StringBuilder;

    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    const-class v8, Llyiahf/vczjk/n77;

    invoke-virtual {v8}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v8, " "

    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " executed; reschedule = "

    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v3, v6, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/n77;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/gs2;

    invoke-interface {v3, v4, v0}, Llyiahf/vczjk/gs2;->OooO0o0(Llyiahf/vczjk/jqa;Z)V

    goto :goto_5

    :cond_6
    monitor-exit v2

    return-void

    :goto_6
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    throw v0

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uv6;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v2, v3, v0, v1}, Llyiahf/vczjk/uv6;->OooOoO0(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;Z)V

    return-void

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/IPackageEnableStateChangeListener;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/uv6;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/List;

    new-instance v3, Llyiahf/vczjk/rw2;

    invoke-direct {v3, v2}, Llyiahf/vczjk/rw2;-><init>(Ljava/util/List;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/uv6;->OooOo(Lgithub/tornaco/android/thanos/core/util/function/Predicate;)V

    :try_start_6
    invoke-interface {v0}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    move-result-object v1

    invoke-interface {v1}, Landroid/os/IBinder;->isBinderAlive()Z

    move-result v1

    if-eqz v1, :cond_7

    invoke-interface {v0, v2}, Lgithub/tornaco/android/thanos/core/pm/IPackageEnableStateChangeListener;->onPackageEnableStateChanged(Ljava/util/List;)V
    :try_end_6
    .catch Landroid/os/RemoteException; {:try_start_6 .. :try_end_6} :catch_1

    goto :goto_7

    :catch_1
    move-exception v0

    const-string v1, "freezeAllSmartFreezePackages, call onPackageEnableStateChanged error"

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_7
    :goto_7
    return-void

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/q95;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroid/os/HandlerThread;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv2;

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/q95;->OooO0O0(Landroid/os/HandlerThread;Llyiahf/vczjk/q95;Llyiahf/vczjk/gv2;)V

    return-void

    :pswitch_8
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mo0;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v2

    if-eqz v2, :cond_8

    goto :goto_8

    :cond_8
    :try_start_7
    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mo0;->OooO00o(Ljava/lang/Object;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    goto :goto_8

    :catchall_5
    move-exception v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mo0;->OooO0O0(Ljava/lang/Throwable;)V

    :goto_8
    return-void

    :pswitch_9
    new-instance v0, Llyiahf/vczjk/fz3;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/infinite/IRemovePackageCallback;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/o000OO;

    const/16 v3, 0x1b

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Lnow/fortuitous/app/infinite/OooO00o;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Ljava/lang/String;

    invoke-virtual {v2, v3, v0, v1}, Lnow/fortuitous/app/infinite/OooO00o;->OooOooo(Ljava/lang/String;Llyiahf/vczjk/fz3;Llyiahf/vczjk/o000OO;)V

    return-void

    :pswitch_a
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/app/infinite/OooO00o;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v0, v2}, Lnow/fortuitous/app/infinite/OooO00o;->OooOo0(Ljava/lang/String;)Z

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v3, Lgithub/tornaco/android/thanos/core/app/infinite/IAddPackageCallback;

    if-eqz v2, :cond_9

    if-eqz v3, :cond_a

    invoke-virtual {v0}, Lnow/fortuitous/app/infinite/OooO00o;->OooOo0o()I

    move-result v0

    invoke-interface {v3, v0}, Lgithub/tornaco/android/thanos/core/app/infinite/IAddPackageCallback;->onSuccess(I)V

    goto :goto_9

    :cond_9
    if-eqz v3, :cond_a

    const-string v0, "Fail add package."

    invoke-interface {v3, v0, v1}, Lgithub/tornaco/android/thanos/core/app/infinite/IAddPackageCallback;->onError(Ljava/lang/String;I)V

    :cond_a
    :goto_9
    return-void

    :pswitch_b
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ra0;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ng0;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/concurrent/ThreadPoolExecutor;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :try_start_8
    iget-object v0, v0, Llyiahf/vczjk/ra0;->OooO00o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/u34;->OooOOo0(Landroid/content/Context;)Llyiahf/vczjk/pa3;

    move-result-object v0

    if-eqz v0, :cond_b

    iget-object v3, v0, Llyiahf/vczjk/ol2;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ql2;

    check-cast v3, Llyiahf/vczjk/oa3;

    iget-object v4, v3, Llyiahf/vczjk/oa3;->OooO0Oo:Ljava/lang/Object;

    monitor-enter v4
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    :try_start_9
    iput-object v2, v3, Llyiahf/vczjk/oa3;->OooO0o:Ljava/util/concurrent/ThreadPoolExecutor;

    monitor-exit v4
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_7

    :try_start_a
    iget-object v0, v0, Llyiahf/vczjk/ol2;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ql2;

    new-instance v3, Llyiahf/vczjk/tl2;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/tl2;-><init>(Llyiahf/vczjk/ng0;Ljava/util/concurrent/ThreadPoolExecutor;)V

    invoke-interface {v0, v3}, Llyiahf/vczjk/ql2;->OooO00o(Llyiahf/vczjk/ng0;)V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    goto :goto_b

    :catchall_6
    move-exception v0

    goto :goto_a

    :catchall_7
    move-exception v0

    :try_start_b
    monitor-exit v4
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    :try_start_c
    throw v0

    :cond_b
    new-instance v0, Ljava/lang/RuntimeException;

    const-string v3, "EmojiCompat font provider not available on this device."

    invoke-direct {v0, v3}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_6

    :goto_a
    invoke-virtual {v1, v0}, Llyiahf/vczjk/ng0;->OoooO00(Ljava/lang/Throwable;)V

    invoke-virtual {v2}, Ljava/util/concurrent/ThreadPoolExecutor;->shutdown()V

    :goto_b
    return-void

    :pswitch_c
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Landroidx/fragment/app/OooOO0O;

    const-string v1, "this$0"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroidx/fragment/app/o0O0O00;

    iget-object v1, v1, Landroidx/fragment/app/o0O0O00;->OooO0OO:Landroidx/fragment/app/Oooo0;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Landroidx/fragment/app/o0O0O00;

    iget-object v2, v2, Landroidx/fragment/app/o0O0O00;->OooO0OO:Landroidx/fragment/app/Oooo0;

    sget-object v3, Llyiahf/vczjk/id3;->OooO00o:Llyiahf/vczjk/nd3;

    const-string v3, "inFragment"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "outFragment"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, v0, Landroidx/fragment/app/OooOO0O;->OooOOOO:Z

    if-eqz v0, :cond_c

    invoke-virtual {v2}, Landroidx/fragment/app/Oooo0;->getEnterTransitionCallback()Llyiahf/vczjk/fl8;

    goto :goto_c

    :cond_c
    invoke-virtual {v1}, Landroidx/fragment/app/Oooo0;->getEnterTransitionCallback()Llyiahf/vczjk/fl8;

    :goto_c
    return-void

    :pswitch_d
    const-string v0, "$container"

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroid/view/ViewGroup;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "this$0"

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Landroidx/fragment/app/OooO0OO;

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/view/View;

    invoke-virtual {v1, v0}, Landroid/view/ViewGroup;->endViewTransition(Landroid/view/View;)V

    iget-object v0, v2, Landroidx/fragment/app/OooO0OO;->OooO0OO:Landroidx/fragment/app/OooO0o;

    iget-object v0, v0, Landroidx/fragment/app/OooOO0;->OooO00o:Landroidx/fragment/app/o0O0O00;

    invoke-virtual {v0, v2}, Landroidx/fragment/app/o0O0O00;->OooO0OO(Llyiahf/vczjk/ny8;)V

    return-void

    :pswitch_e
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a27;

    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/l12;

    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ho0;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/Throwable;

    invoke-interface {v1, v0, v2}, Llyiahf/vczjk/ho0;->OooOooo(Llyiahf/vczjk/wn0;Ljava/lang/Throwable;)V

    return-void

    :pswitch_f
    iget-object v0, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a27;

    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/l12;

    iget-object v1, v0, Llyiahf/vczjk/l12;->OooOOO:Llyiahf/vczjk/wn0;

    invoke-interface {v1}, Llyiahf/vczjk/wn0;->isCanceled()Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ho0;

    if-eqz v1, :cond_d

    new-instance v1, Ljava/io/IOException;

    const-string v3, "Canceled"

    invoke-direct {v1, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    invoke-interface {v2, v0, v1}, Llyiahf/vczjk/ho0;->OooOooo(Llyiahf/vczjk/wn0;Ljava/lang/Throwable;)V

    goto :goto_d

    :cond_d
    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/hs7;

    invoke-interface {v2, v0, v1}, Llyiahf/vczjk/ho0;->Oooo0oo(Llyiahf/vczjk/wn0;Llyiahf/vczjk/hs7;)V

    :goto_d
    return-void

    :pswitch_10
    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v4, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Lnow/fortuitous/app/OooO00o;

    iget-object v4, v4, Lnow/fortuitous/app/OooO00o;->Oooo0:Landroid/os/RemoteCallbackList;

    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->beginBroadcast()I

    move-result v5

    move v6, v1

    :goto_e
    if-ge v6, v5, :cond_e

    :try_start_d
    invoke-virtual {v4, v6}, Landroid/os/RemoteCallbackList;->getBroadcastItem(I)Landroid/os/IInterface;

    move-result-object v7

    check-cast v7, Lgithub/tornaco/android/thanos/core/app/activity/ITopPackageChangeListener;

    invoke-interface {v7, v2, v3}, Lgithub/tornaco/android/thanos/core/app/activity/ITopPackageChangeListener;->onChange(Lgithub/tornaco/android/thanos/core/pm/Pkg;Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_8

    goto :goto_f

    :catchall_8
    move-exception v7

    :try_start_e
    const-string v8, "Call onChange"

    new-array v9, v1, [Ljava/lang/Object;

    invoke-static {v8, v9, v7}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_9

    :goto_f
    add-int/2addr v6, v0

    goto :goto_e

    :catchall_9
    move-exception v0

    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->finishBroadcast()V

    throw v0

    :cond_e
    invoke-virtual {v4}, Landroid/os/RemoteCallbackList;->finishBroadcast()V

    return-void

    :pswitch_11
    iget-object v1, p0, Llyiahf/vczjk/oOO0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/a;

    iget-object v2, p0, Llyiahf/vczjk/oOO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v3, p0, Llyiahf/vczjk/oOO0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Ljava/lang/String;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/a;->OooOooo(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/a;->OooOooO(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    const-string v4, "forceStopPackage Package done: %s, reason: %s"

    filled-new-array {v2, v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4, v3}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/oOO00OO;

    invoke-direct {v3, v1, v2, v0}, Llyiahf/vczjk/oOO00OO;-><init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V

    const-wide/16 v4, 0x1f4

    invoke-virtual {v1, v3, v4, v5}, Llyiahf/vczjk/td9;->OooO0oO(Ljava/lang/Runnable;J)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
