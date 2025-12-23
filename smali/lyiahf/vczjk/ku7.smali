.class public final synthetic Llyiahf/vczjk/ku7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ku7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ku7;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 12

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/ku7;->OooOOO:Ljava/lang/Object;

    iget v2, p0, Llyiahf/vczjk/ku7;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    check-cast v1, Llyiahf/vczjk/oqa;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    sget-object v3, Llyiahf/vczjk/od9;->OooOOo:Ljava/lang/String;

    iget-object v3, v1, Llyiahf/vczjk/oqa;->OooOO0o:Landroid/content/Context;

    const/16 v4, 0x22

    if-lt v2, v4, :cond_0

    invoke-static {v3}, Llyiahf/vczjk/g84;->OooO0O0(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    move-result-object v2

    invoke-virtual {v2}, Landroid/app/job/JobScheduler;->cancelAll()V

    :cond_0
    const-string v2, "jobscheduler"

    invoke-virtual {v3, v2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/app/job/JobScheduler;

    invoke-static {v3, v2}, Llyiahf/vczjk/od9;->OooO0o0(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_1

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/app/job/JobInfo;

    invoke-virtual {v4}, Landroid/app/job/JobInfo;->getId()I

    move-result v4

    invoke-static {v2, v4}, Llyiahf/vczjk/od9;->OooO00o(Landroid/app/job/JobScheduler;I)V

    goto :goto_0

    :cond_1
    iget-object v2, v1, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    invoke-virtual {v2}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v3

    iget-object v4, v3, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v4}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    iget-object v3, v3, Llyiahf/vczjk/bra;->OooOO0o:Llyiahf/vczjk/qw7;

    invoke-virtual {v3}, Llyiahf/vczjk/yd7;->OooO00o()Llyiahf/vczjk/la9;

    move-result-object v5

    :try_start_0
    invoke-virtual {v4}, Llyiahf/vczjk/ru7;->beginTransaction()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    invoke-interface {v5}, Llyiahf/vczjk/la9;->OooOOOo()I

    invoke-virtual {v4}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-virtual {v4}, Llyiahf/vczjk/ru7;->endTransaction()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    iget-object v3, v1, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    iget-object v1, v1, Llyiahf/vczjk/oqa;->OooOOOo:Ljava/util/List;

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/t88;->OooO0O0(Llyiahf/vczjk/wh1;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    return-object v0

    :catchall_0
    move-exception v0

    goto :goto_1

    :catchall_1
    move-exception v0

    :try_start_3
    invoke-virtual {v4}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_1
    invoke-virtual {v3, v5}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    throw v0

    :pswitch_0
    check-cast v1, Llyiahf/vczjk/dqa;

    sget-object v2, Llyiahf/vczjk/yn2;->OooO00o:Ljava/lang/String;

    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    invoke-static {v1, v2}, Llyiahf/vczjk/dqa;->OooOooo(Llyiahf/vczjk/dqa;Ljava/util/HashSet;)Z

    move-result v2

    if-nez v2, :cond_3

    iget-object v2, v1, Llyiahf/vczjk/dqa;->OooO0OO:Llyiahf/vczjk/oqa;

    iget-object v3, v2, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    iget-object v4, v2, Llyiahf/vczjk/oqa;->OooOOO0:Llyiahf/vczjk/wh1;

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->beginTransaction()V

    :try_start_4
    invoke-static {v3, v4, v1}, Llyiahf/vczjk/v34;->OooOo0O(Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/wh1;Llyiahf/vczjk/dqa;)V

    invoke-static {v1}, Llyiahf/vczjk/yn2;->OooO00o(Llyiahf/vczjk/dqa;)Z

    move-result v1

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->endTransaction()V

    if-eqz v1, :cond_2

    iget-object v1, v2, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    iget-object v2, v2, Llyiahf/vczjk/oqa;->OooOOOo:Ljava/util/List;

    invoke-static {v4, v1, v2}, Llyiahf/vczjk/t88;->OooO0O0(Llyiahf/vczjk/wh1;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    :cond_2
    return-object v0

    :catchall_2
    move-exception v0

    invoke-virtual {v3}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "WorkContinuation has cycles ("

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_1
    check-cast v1, Llyiahf/vczjk/xo8;

    iget-object v0, v1, Llyiahf/vczjk/xo8;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v0

    return-object v0

    :pswitch_2
    sget v2, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;->OoooO0O:I

    check-cast v1, Lgithub/tornaco/practice/honeycomb/locker/ui/setup/WhiteListComponentViewerActivity;

    invoke-virtual {v1}, Landroid/app/Activity;->finish()V

    return-object v0

    :pswitch_3
    sget v2, Lnow/fortuitous/thanos/power/wakelock/WakeLockBlockerActivity;->OoooO0O:I

    check-cast v1, Lnow/fortuitous/thanos/power/wakelock/WakeLockBlockerActivity;

    invoke-virtual {v1}, Landroid/app/Activity;->finish()V

    return-object v0

    :pswitch_4
    check-cast v1, Llyiahf/vczjk/mka;

    iget-object v0, v1, Llyiahf/vczjk/mka;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_5
    check-cast v1, Llyiahf/vczjk/w83;

    invoke-static {v1}, Llyiahf/vczjk/w83;->OooO0O0(Llyiahf/vczjk/w83;)V

    return-object v0

    :pswitch_6
    new-instance v0, Llyiahf/vczjk/tq7;

    check-cast v1, Llyiahf/vczjk/v89;

    iget-object v1, v1, Llyiahf/vczjk/v89;->OooO0o:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/tq7;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_7
    sget v2, Lgithub/tornaco/android/thanos/support/subscribe/SubscribeActivity;->OoooO0O:I

    check-cast v1, Lgithub/tornaco/android/thanos/support/subscribe/SubscribeActivity;

    invoke-virtual {v1}, Landroid/app/Activity;->finish()V

    return-object v0

    :pswitch_8
    sget v2, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/StatsActivity;->OoooO0O:I

    check-cast v1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/StatsActivity;

    invoke-virtual {v1}, Landroid/app/Activity;->finish()V

    return-object v0

    :pswitch_9
    check-cast v1, Llyiahf/vczjk/n19;

    iget-object v2, v1, Llyiahf/vczjk/n19;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/j19;

    iget-object v2, v2, Llyiahf/vczjk/j19;->OooO0OO:Llyiahf/vczjk/ur0;

    sget-object v3, Llyiahf/vczjk/ur0;->OooOOO:Llyiahf/vczjk/ur0;

    iget-object v4, v1, Llyiahf/vczjk/n19;->OooO0O0:Landroid/content/Context;

    if-ne v2, v3, :cond_4

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->resetStartRecordsBlocked()V

    :cond_4
    sget-object v3, Llyiahf/vczjk/ur0;->OooOOO0:Llyiahf/vczjk/ur0;

    if-ne v2, v3, :cond_5

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->resetStartRecordsAllowed()V

    :cond_5
    sget-object v3, Llyiahf/vczjk/ur0;->OooOOOO:Llyiahf/vczjk/ur0;

    if-ne v2, v3, :cond_6

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->resetStartRecordsBlocked()V

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->resetStartRecordsAllowed()V

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/n19;->OooO0o()V

    return-object v0

    :pswitch_a
    check-cast v1, Llyiahf/vczjk/cs8;

    iget-object v1, v1, Llyiahf/vczjk/cs8;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    return-object v0

    :pswitch_b
    check-cast v1, Llyiahf/vczjk/yo8;

    iget-object v1, v1, Llyiahf/vczjk/yo8;->OooO00o:Llyiahf/vczjk/ie;

    iget-object v1, v1, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/theme/ThemeActivity;

    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "getApplicationContext(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v2

    invoke-virtual {v2}, Landroid/content/ContentResolver;->getPersistedUriPermissions()Ljava/util/List;

    move-result-object v3

    const-string v4, "getPersistedUriPermissions(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_7
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Landroid/content/UriPermission;

    invoke-virtual {v6}, Landroid/content/UriPermission;->isReadPermission()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-virtual {v6}, Landroid/content/UriPermission;->isWritePermission()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-virtual {v6}, Landroid/content/UriPermission;->getUri()Landroid/net/Uri;

    move-result-object v6

    const-string v7, "getUri(...)"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v6}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    move-result-object v6

    const-string v7, "com.android.externalstorage.documents"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_7

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_8
    new-instance v3, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v4, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_9

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/content/UriPermission;

    invoke-virtual {v6}, Landroid/content/UriPermission;->getUri()Landroid/net/Uri;

    move-result-object v6

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_9
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_a
    :goto_4
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    const-string v8, "/tree/"

    if-eqz v7, :cond_c

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/net/Uri;

    invoke-virtual {v7}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_b

    invoke-static {v7, v8, v7}, Llyiahf/vczjk/z69;->Oooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    goto :goto_5

    :cond_b
    const/4 v7, 0x0

    :goto_5
    if-eqz v7, :cond_a

    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_c
    sget-object v6, Llyiahf/vczjk/kd2;->OooO00o:Llyiahf/vczjk/on7;

    new-instance v6, Ljava/util/ArrayList;

    invoke-static {v4, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v6, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_d

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    invoke-static {v1, v5}, Llyiahf/vczjk/kd2;->OooO00o(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_d
    invoke-static {v6}, Llyiahf/vczjk/d21;->Ooooooo(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Ljava/util/ArrayList;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_7
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_11

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/lang/String;

    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    move-result v9

    if-eqz v9, :cond_e

    goto :goto_8

    :cond_e
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :cond_f
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_10

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/String;

    invoke-static {v10, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_f

    invoke-static {v7, v10}, Llyiahf/vczjk/vo6;->OooOO0(Ljava/lang/String;Ljava/lang/String;)Z

    move-result v10

    if-eqz v10, :cond_f

    goto :goto_7

    :cond_10
    :goto_8
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_7

    :cond_11
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_12
    :goto_9
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_14

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/net/Uri;

    invoke-virtual {v4}, Landroid/net/Uri;->getPath()Ljava/lang/String;

    move-result-object v6

    if-nez v6, :cond_13

    const-string v6, ""

    :cond_13
    invoke-static {v6, v8, v6}, Llyiahf/vczjk/z69;->Oooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-static {v1, v6}, Llyiahf/vczjk/kd2;->OooO00o(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_12

    const/4 v6, 0x3

    invoke-virtual {v2, v4, v6}, Landroid/content/ContentResolver;->releasePersistableUriPermission(Landroid/net/Uri;I)V

    new-instance v6, Ljava/lang/StringBuilder;

    const-string v7, "Removed redundant URI permission => "

    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    const-string v6, "SimpleStorage"

    invoke-static {v6, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_9

    :cond_14
    return-object v0

    :pswitch_c
    check-cast v1, Llyiahf/vczjk/zl8;

    iget-object v0, v1, Llyiahf/vczjk/zl8;->OooO0Oo:Llyiahf/vczjk/wl;

    return-object v0

    :pswitch_d
    check-cast v1, Llyiahf/vczjk/yd7;

    invoke-virtual {v1}, Llyiahf/vczjk/yd7;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    iget-object v1, v1, Llyiahf/vczjk/yd7;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ru7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ru7;->compileStatement(Ljava/lang/String;)Llyiahf/vczjk/la9;

    move-result-object v0

    return-object v0

    :pswitch_e
    return-object v1

    :pswitch_f
    check-cast v1, Llyiahf/vczjk/h68;

    invoke-interface {v1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/vj7;

    invoke-direct {v3, v1}, Llyiahf/vczjk/vj7;-><init>(Llyiahf/vczjk/h68;)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    return-object v0

    :pswitch_10
    check-cast v1, Llyiahf/vczjk/lha;

    invoke-static {v1}, Llyiahf/vczjk/jp8;->OooOoOO(Llyiahf/vczjk/lha;)Llyiahf/vczjk/b68;

    move-result-object v0

    return-object v0

    :pswitch_11
    check-cast v1, Llyiahf/vczjk/lm6;

    invoke-virtual {v1}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0

    :pswitch_12
    check-cast v1, Ljava/util/concurrent/Callable;

    invoke-interface {v1}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :pswitch_13
    check-cast v1, Ljava/lang/Runnable;

    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_13
        :pswitch_12
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
