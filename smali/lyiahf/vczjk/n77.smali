.class public final Llyiahf/vczjk/n77;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooOO0o:Ljava/lang/String;


# instance fields
.field public final OooO:Ljava/util/HashSet;

.field public OooO00o:Landroid/os/PowerManager$WakeLock;

.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Llyiahf/vczjk/wh1;

.field public final OooO0Oo:Llyiahf/vczjk/rqa;

.field public final OooO0o:Ljava/util/HashMap;

.field public final OooO0o0:Landroidx/work/impl/WorkDatabase;

.field public final OooO0oO:Ljava/util/HashMap;

.field public final OooO0oo:Ljava/util/HashMap;

.field public final OooOO0:Ljava/util/ArrayList;

.field public final OooOO0O:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "Processor"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/rqa;Landroidx/work/impl/WorkDatabase;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/n77;->OooO0OO:Llyiahf/vczjk/wh1;

    iput-object p3, p0, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    iput-object p4, p0, Llyiahf/vczjk/n77;->OooO0o0:Landroidx/work/impl/WorkDatabase;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO0oO:Ljava/util/HashMap;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO0o:Ljava/util/HashMap;

    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO:Ljava/util/HashSet;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooOO0:Ljava/util/ArrayList;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO00o:Landroid/os/PowerManager$WakeLock;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n77;->OooO0oo:Ljava/util/HashMap;

    return-void
.end method

.method public static OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/wra;I)Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    if-eqz p1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/wra;->OooOOO0:Llyiahf/vczjk/x74;

    new-instance v1, Llyiahf/vczjk/lra;

    invoke-direct {v1, p2}, Llyiahf/vczjk/lra;-><init>(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/k84;->OooOOoo(Ljava/util/concurrent/CancellationException;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v1, "WorkerWrapper interrupted for "

    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, v0, p0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    const/4 p0, 0x1

    return p0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v1, "WorkerWrapper could not be found for "

    invoke-direct {p2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, v0, p0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/gs2;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/n77;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public final OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/wra;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wra;

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-nez v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooO0oO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wra;

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/n77;->OooO0oo:Ljava/util/HashMap;

    invoke-virtual {v2, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    if-eqz v1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter p1

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/n77;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    sget-object v2, Llyiahf/vczjk/jd9;->OooOo0O:Ljava/lang/String;

    new-instance v2, Landroid/content/Intent;

    const-class v3, Landroidx/work/impl/foreground/SystemForegroundService;

    invoke-direct {v2, v1, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v1, "ACTION_STOP_FOREGROUND"

    invoke-virtual {v2, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    invoke-virtual {v1, v2}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception v1

    :try_start_2
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    const-string v4, "Unable to stop foreground service"

    invoke-virtual {v2, v3, v4, v1}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/n77;->OooO00o:Landroid/os/PowerManager$WakeLock;

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Landroid/os/PowerManager$WakeLock;->release()V

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/n77;->OooO00o:Landroid/os/PowerManager$WakeLock;

    goto :goto_2

    :catchall_1
    move-exception v0

    goto :goto_3

    :cond_2
    :goto_2
    monitor-exit p1

    goto :goto_4

    :goto_3
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw v0

    :cond_3
    :goto_4
    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/wra;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooO0o:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wra;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooO0oO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wra;

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/g29;Llyiahf/vczjk/xo8;)Z
    .locals 12

    const-string p2, "Work "

    iget-object v0, p1, Llyiahf/vczjk/g29;->OooO00o:Llyiahf/vczjk/jqa;

    iget-object v1, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/n77;->OooO0o0:Landroidx/work/impl/WorkDatabase;

    new-instance v3, Llyiahf/vczjk/b85;

    invoke-direct {v3, p0, v9, v1}, Llyiahf/vczjk/b85;-><init>(Llyiahf/vczjk/n77;Ljava/util/ArrayList;Ljava/lang/String;)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    move-result-object v2

    move-object v8, v2

    check-cast v8, Llyiahf/vczjk/ara;

    const/4 v2, 0x0

    if-nez v8, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "Didn\'t find WorkSpec for id "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, p2, v1}, Llyiahf/vczjk/o55;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    new-instance p2, Llyiahf/vczjk/tm4;

    const/16 v1, 0xc

    invoke-direct {p2, v1, p0, v0}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    return v2

    :cond_0
    iget-object v10, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v10

    :try_start_0
    iget-object v3, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :try_start_1
    invoke-virtual {p0, v1}, Llyiahf/vczjk/n77;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/wra;

    move-result-object v4

    const/4 v11, 0x1

    if-eqz v4, :cond_1

    move v4, v11

    goto :goto_0

    :cond_1
    move v4, v2

    :goto_0
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    if-eqz v4, :cond_3

    :try_start_2
    iget-object v3, p0, Llyiahf/vczjk/n77;->OooO0oo:Ljava/util/HashMap;

    invoke-virtual {v3, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/g29;

    iget-object v3, v3, Llyiahf/vczjk/g29;->OooO00o:Llyiahf/vczjk/jqa;

    iget v3, v3, Llyiahf/vczjk/jqa;->OooO0O0:I

    iget v4, v0, Llyiahf/vczjk/jqa;->OooO0O0:I

    if-ne v3, v4, :cond_2

    invoke-interface {v1, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, " is already enqueued for processing"

    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_1

    :catchall_0
    move-exception v0

    move-object p1, v0

    move-object v6, p0

    goto/16 :goto_4

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    new-instance p2, Llyiahf/vczjk/tm4;

    const/16 v1, 0xc

    invoke-direct {p2, v1, p0, v0}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    :goto_1
    monitor-exit v10
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    return v2

    :cond_3
    :try_start_3
    iget p2, v8, Llyiahf/vczjk/ara;->OooOo00:I

    iget v3, v0, Llyiahf/vczjk/jqa;->OooO0O0:I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    if-eq p2, v3, :cond_4

    :try_start_4
    iget-object p1, p0, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    new-instance p2, Llyiahf/vczjk/tm4;

    const/16 v1, 0xc

    invoke-direct {p2, v1, p0, v0}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    monitor-exit v10
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    return v2

    :cond_4
    :try_start_5
    new-instance v2, Llyiahf/vczjk/ex9;

    iget-object v3, p0, Llyiahf/vczjk/n77;->OooO0O0:Landroid/content/Context;

    iget-object v4, p0, Llyiahf/vczjk/n77;->OooO0OO:Llyiahf/vczjk/wh1;

    iget-object v5, p0, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    iget-object v7, p0, Llyiahf/vczjk/n77;->OooO0o0:Landroidx/work/impl/WorkDatabase;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    move-object v6, p0

    :try_start_6
    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/ex9;-><init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/rqa;Llyiahf/vczjk/n77;Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/ara;Ljava/util/ArrayList;)V

    new-instance p2, Llyiahf/vczjk/wra;

    invoke-direct {p2, v2}, Llyiahf/vczjk/wra;-><init>(Llyiahf/vczjk/ex9;)V

    iget-object v2, p2, Llyiahf/vczjk/wra;->OooO0Oo:Llyiahf/vczjk/rqa;

    iget-object v2, v2, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object v3

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2, v3}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/sra;

    const/4 v4, 0x0

    invoke-direct {v3, p2, v4}, Llyiahf/vczjk/sra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/yo1;)V

    invoke-static {v2, v3}, Llyiahf/vczjk/cp7;->OooOooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/qo0;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/oOO0;

    const/16 v4, 0xd

    invoke-direct {v3, p0, v2, v4, p2}, Llyiahf/vczjk/oOO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iget-object v4, v6, Llyiahf/vczjk/n77;->OooO0Oo:Llyiahf/vczjk/rqa;

    iget-object v4, v4, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    iget-object v2, v2, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/o0o0Oo;->OooO00o(Ljava/lang/Runnable;Ljava/util/concurrent/Executor;)V

    iget-object v2, v6, Llyiahf/vczjk/n77;->OooO0oO:Ljava/util/HashMap;

    invoke-virtual {v2, v1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance p2, Ljava/util/HashSet;

    invoke-direct {p2}, Ljava/util/HashSet;-><init>()V

    invoke-virtual {p2, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    iget-object p1, v6, Llyiahf/vczjk/n77;->OooO0oo:Ljava/util/HashMap;

    invoke-virtual {p1, v1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit v10
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/n77;->OooOO0o:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-class v2, Llyiahf/vczjk/n77;

    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ": processing "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return v11

    :catchall_1
    move-exception v0

    :goto_2
    move-object p1, v0

    goto :goto_4

    :catchall_2
    move-exception v0

    move-object v6, p0

    goto :goto_2

    :catchall_3
    move-exception v0

    move-object v6, p0

    :goto_3
    move-object p1, v0

    :try_start_7
    monitor-exit v3
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    :try_start_8
    throw p1

    :catchall_4
    move-exception v0

    goto :goto_3

    :goto_4
    monitor-exit v10
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/gs2;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/n77;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method
