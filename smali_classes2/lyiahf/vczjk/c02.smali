.class public final synthetic Llyiahf/vczjk/c02;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/c02;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 11

    const/4 v0, 0x3

    const/4 v1, 0x0

    iget v2, p0, Llyiahf/vczjk/c02;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/iqa;

    iget-object v2, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/UUID;

    iget-object v3, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qb3;

    iget-object v4, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v4, Landroid/content/Context;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v2

    iget-object v5, v0, Llyiahf/vczjk/iqa;->OooO0OO:Llyiahf/vczjk/bra;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/bra;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/ara;

    move-result-object v5

    if-eqz v5, :cond_3

    iget-object v6, v5, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    invoke-virtual {v6}, Llyiahf/vczjk/lqa;->OooO00o()Z

    move-result v6

    if-nez v6, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/iqa;->OooO0O0:Llyiahf/vczjk/n77;

    const-string v6, "Moving WorkSpec ("

    iget-object v7, v0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v7

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, ") to the foreground"

    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v8, v9, v6}, Llyiahf/vczjk/o55;->OooOOO0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v6, v0, Llyiahf/vczjk/n77;->OooO0oO:Ljava/util/HashMap;

    invoke-virtual {v6, v2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/wra;

    if-eqz v6, :cond_2

    iget-object v8, v0, Llyiahf/vczjk/n77;->OooO00o:Landroid/os/PowerManager$WakeLock;

    if-nez v8, :cond_0

    iget-object v8, v0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    const-string v9, "ProcessorForegroundLck"

    invoke-static {v8, v9}, Llyiahf/vczjk/fla;->OooO00o(Landroid/content/Context;Ljava/lang/String;)Landroid/os/PowerManager$WakeLock;

    move-result-object v8

    iput-object v8, v0, Llyiahf/vczjk/n77;->OooO00o:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v8}, Landroid/os/PowerManager$WakeLock;->acquire()V

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_2

    :cond_0
    :goto_0
    iget-object v8, v0, Llyiahf/vczjk/n77;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {v8, v2, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v2, v0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    iget-object v6, v6, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    invoke-static {v6}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v6

    invoke-static {v2, v6, v3}, Llyiahf/vczjk/jd9;->OooO0O0(Landroid/content/Context;Llyiahf/vczjk/jqa;Llyiahf/vczjk/qb3;)Landroid/content/Intent;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v8, 0x1a

    if-lt v6, v8, :cond_1

    invoke-static {v0, v2}, Llyiahf/vczjk/d31;->OooOOo0(Landroid/content/Context;Landroid/content/Intent;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v0, v2}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    :cond_2
    :goto_1
    monitor-exit v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v5}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/jd9;->OooOo0O:Ljava/lang/String;

    new-instance v2, Landroid/content/Intent;

    const-class v5, Landroidx/work/impl/foreground/SystemForegroundService;

    invoke-direct {v2, v4, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v5, "ACTION_NOTIFY"

    invoke-virtual {v2, v5}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    iget v5, v3, Llyiahf/vczjk/qb3;->OooO00o:I

    const-string v6, "KEY_NOTIFICATION_ID"

    invoke-virtual {v2, v6, v5}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    const-string v5, "KEY_FOREGROUND_SERVICE_TYPE"

    iget v6, v3, Llyiahf/vczjk/qb3;->OooO0O0:I

    invoke-virtual {v2, v5, v6}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    const-string v5, "KEY_NOTIFICATION"

    iget-object v3, v3, Llyiahf/vczjk/qb3;->OooO0OO:Landroid/app/Notification;

    invoke-virtual {v2, v5, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    iget-object v3, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    const-string v5, "KEY_WORKSPEC_ID"

    invoke-virtual {v2, v5, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    const-string v3, "KEY_GENERATION"

    iget v0, v0, Llyiahf/vczjk/jqa;->OooO0O0:I

    invoke-virtual {v2, v3, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    invoke-virtual {v4, v2}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    return-object v1

    :goto_2
    :try_start_1
    monitor-exit v7
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0

    :cond_3
    const-string v0, "Calls to setForegroundAsync() must complete before a ListenableWorker signals completion of work by returning an instance of Result."

    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cm4;

    const/4 v1, 0x1

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg5;

    iget-object v2, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    iput-object v2, v0, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_3

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yo9;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_3
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    new-instance v2, Llyiahf/vczjk/t08;

    iget-object v3, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/h48;

    iget-object v4, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qs5;

    iget-object v5, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v5, Landroid/content/Context;

    invoke-direct {v2, v3, v4, v5, v1}, Llyiahf/vczjk/t08;-><init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/p29;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    iget-object v3, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xr1;

    invoke-static {v3, v1, v1, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ki2;

    iget-object v1, v0, Llyiahf/vczjk/ki2;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    iget-object v2, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/f62;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/p13;

    iput-object v1, v0, Llyiahf/vczjk/ki2;->OooO0Oo:Llyiahf/vczjk/p13;

    iget-object v1, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/p13;

    iput-object v1, v0, Llyiahf/vczjk/ki2;->OooO0o0:Llyiahf/vczjk/p13;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_3
    iget-object v2, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/zl8;

    invoke-virtual {v2}, Llyiahf/vczjk/zl8;->OooO0OO()Llyiahf/vczjk/am8;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    iget-object v5, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/xr1;

    if-ne v3, v4, :cond_5

    iget-object v3, v2, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v3}, Llyiahf/vczjk/c9;->OooO0Oo()Llyiahf/vczjk/kb5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    iget-object v3, v3, Llyiahf/vczjk/kb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v3, v4}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    new-instance v3, Llyiahf/vczjk/fk5;

    iget-object v4, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/gi;

    invoke-direct {v3, v4, v1}, Llyiahf/vczjk/fk5;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v1, v1, v3, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v3, Llyiahf/vczjk/gk5;

    invoke-direct {v3, v2, v1}, Llyiahf/vczjk/gk5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v1, v1, v3, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_4

    :cond_5
    new-instance v3, Llyiahf/vczjk/hk5;

    invoke-direct {v3, v2, v1}, Llyiahf/vczjk/hk5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v1, v1, v3, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hp;

    iget-object v2, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v3, 0x4

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    :goto_4
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ov5;

    iget-object v0, v0, Llyiahf/vczjk/ov5;->OooO0O0:Llyiahf/vczjk/su5;

    invoke-virtual {v0}, Llyiahf/vczjk/su5;->OooO0oO()Llyiahf/vczjk/ku5;

    move-result-object v0

    if-eqz v0, :cond_6

    iget-object v0, v0, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    if-eqz v0, :cond_6

    iget-object v0, v0, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    iget-object v0, v0, Llyiahf/vczjk/j1;->OooO0o0:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Ljava/lang/String;

    :cond_6
    sget-object v0, Llyiahf/vczjk/bf0;->OooO0Oo:Llyiahf/vczjk/bf0;

    const-string v0, "TimeOfADay"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n3;

    iget-object v0, v0, Llyiahf/vczjk/n3;->OooO0O0:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_5

    :cond_7
    sget-object v0, Llyiahf/vczjk/af0;->OooO0Oo:Llyiahf/vczjk/af0;

    const-string v0, "RegularInterval"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_8

    sget v0, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;->OoooO0O:I

    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Landroid/content/Context;

    const-string v1, "context"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Landroid/content/Intent;

    const-class v2, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-direct {v1, v0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    iget-object v0, p0, Llyiahf/vczjk/c02;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wa5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wa5;->OooO00o(Ljava/lang/Object;)V

    :cond_8
    :goto_5
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
