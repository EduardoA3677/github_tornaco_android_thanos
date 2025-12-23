.class public final Llyiahf/vczjk/g52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pa6;
.implements Llyiahf/vczjk/fra;


# static fields
.field public static final OooOoOO:Ljava/lang/String;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Landroid/content/Context;

.field public final OooOOOO:Llyiahf/vczjk/jqa;

.field public final OooOOOo:Llyiahf/vczjk/bd9;

.field public final OooOOo:Ljava/lang/Object;

.field public final OooOOo0:Llyiahf/vczjk/aqa;

.field public OooOOoo:I

.field public final OooOo:Llyiahf/vczjk/g29;

.field public final OooOo0:Llyiahf/vczjk/wd;

.field public final OooOo00:Llyiahf/vczjk/vq;

.field public OooOo0O:Landroid/os/PowerManager$WakeLock;

.field public OooOo0o:Z

.field public volatile OooOoO:Llyiahf/vczjk/r09;

.field public final OooOoO0:Llyiahf/vczjk/qr1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "DelayMetCommandHandler"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;ILlyiahf/vczjk/bd9;Llyiahf/vczjk/g29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g52;->OooOOO0:Landroid/content/Context;

    iput p2, p0, Llyiahf/vczjk/g52;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object p1, p4, Llyiahf/vczjk/g29;->OooO00o:Llyiahf/vczjk/jqa;

    iput-object p1, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    iput-object p4, p0, Llyiahf/vczjk/g52;->OooOo:Llyiahf/vczjk/g29;

    iget-object p1, p3, Llyiahf/vczjk/bd9;->OooOOo0:Llyiahf/vczjk/oqa;

    iget-object p1, p1, Llyiahf/vczjk/oqa;->OooOo0:Llyiahf/vczjk/qx9;

    iget-object p2, p3, Llyiahf/vczjk/bd9;->OooOOO:Llyiahf/vczjk/rqa;

    iget-object p3, p2, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    iput-object p3, p0, Llyiahf/vczjk/g52;->OooOo00:Llyiahf/vczjk/vq;

    iget-object p3, p2, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    iput-object p3, p0, Llyiahf/vczjk/g52;->OooOo0:Llyiahf/vczjk/wd;

    iget-object p2, p2, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    iput-object p2, p0, Llyiahf/vczjk/g52;->OooOoO0:Llyiahf/vczjk/qr1;

    new-instance p2, Llyiahf/vczjk/aqa;

    invoke-direct {p2, p1}, Llyiahf/vczjk/aqa;-><init>(Llyiahf/vczjk/qx9;)V

    iput-object p2, p0, Llyiahf/vczjk/g52;->OooOOo0:Llyiahf/vczjk/aqa;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/g52;->OooOo0o:Z

    iput p1, p0, Llyiahf/vczjk/g52;->OooOOoo:I

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g52;->OooOOo:Ljava/lang/Object;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/g52;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    iget-object v1, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/g52;->OooOOoo:I

    sget-object v3, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    const/4 v4, 0x2

    if-ge v2, v4, :cond_2

    iput v4, p0, Llyiahf/vczjk/g52;->OooOOoo:I

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Stopping work for WorkSpec "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v2, Landroid/content/Intent;

    iget-object v4, p0, Llyiahf/vczjk/g52;->OooOOO0:Landroid/content/Context;

    const-class v5, Landroidx/work/impl/background/systemalarm/SystemAlarmService;

    invoke-direct {v2, v4, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v5, "ACTION_STOP_WORK"

    invoke-virtual {v2, v5}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {v2, v0}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    iget-object v5, p0, Llyiahf/vczjk/g52;->OooOo0:Llyiahf/vczjk/wd;

    new-instance v6, Llyiahf/vczjk/bs;

    iget-object v7, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget p0, p0, Llyiahf/vczjk/g52;->OooOOO:I

    const/4 v8, 0x2

    invoke-direct {v6, v7, v2, p0, v8}, Llyiahf/vczjk/bs;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    invoke-virtual {v5, v6}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    iget-object v2, v7, Llyiahf/vczjk/bd9;->OooOOOo:Llyiahf/vczjk/n77;

    iget-object v6, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    iget-object v8, v2, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v8

    :try_start_0
    invoke-virtual {v2, v6}, Llyiahf/vczjk/n77;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/wra;

    move-result-object v2

    if-eqz v2, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    monitor-exit v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v2, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    new-instance v6, Ljava/lang/StringBuilder;

    const-string v8, "WorkSpec "

    invoke-direct {v6, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " needs to be rescheduled"

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v3, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v1, Landroid/content/Intent;

    const-class v2, Landroidx/work/impl/background/systemalarm/SystemAlarmService;

    invoke-direct {v1, v4, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v2, "ACTION_SCHEDULE_WORK"

    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {v1, v0}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    new-instance v0, Llyiahf/vczjk/bs;

    const/4 v2, 0x2

    invoke-direct {v0, v7, v1, p0, v2}, Llyiahf/vczjk/bs;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    invoke-virtual {v5, v0}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    return-void

    :cond_1
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Processor does not have WorkSpec "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ". No need to reschedule"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v3, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :catchall_0
    move-exception p0

    :try_start_1
    monitor-exit v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p0

    :cond_2
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Already stopped work for "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v3, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public static OooO0OO(Llyiahf/vczjk/g52;)V
    .locals 7

    iget v0, p0, Llyiahf/vczjk/g52;->OooOOoo:I

    if-nez v0, :cond_1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/g52;->OooOOoo:I

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "onAllConstraintsMet for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object v0, v0, Llyiahf/vczjk/bd9;->OooOOOo:Llyiahf/vczjk/n77;

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOo:Llyiahf/vczjk/g29;

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n77;->OooO0o(Llyiahf/vczjk/g29;Llyiahf/vczjk/xo8;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object v0, v0, Llyiahf/vczjk/bd9;->OooOOOO:Llyiahf/vczjk/hra;

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    const-string v2, "Starting timer for "

    iget-object v3, v0, Llyiahf/vczjk/hra;->OooO0Oo:Ljava/lang/Object;

    monitor-enter v3

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/hra;->OooO0o0:Ljava/lang/String;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v4, v5, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hra;->OooO00o(Llyiahf/vczjk/jqa;)V

    new-instance v2, Llyiahf/vczjk/gra;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/gra;-><init>(Llyiahf/vczjk/hra;Llyiahf/vczjk/jqa;)V

    iget-object v4, v0, Llyiahf/vczjk/hra;->OooO0O0:Ljava/util/HashMap;

    invoke-virtual {v4, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v4, v0, Llyiahf/vczjk/hra;->OooO0OO:Ljava/util/HashMap;

    invoke-virtual {v4, v1, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p0, v0, Llyiahf/vczjk/hra;->OooO00o:Llyiahf/vczjk/sw7;

    iget-object p0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast p0, Landroid/os/Handler;

    const-wide/32 v0, 0x927c0

    invoke-virtual {p0, v2, v0, v1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    monitor-exit v3

    return-void

    :catchall_0
    move-exception p0

    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/g52;->OooO0Oo()V

    return-void

    :cond_1
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Already started work for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p0, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, v1, p0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ara;Llyiahf/vczjk/al1;)V
    .locals 1

    instance-of p1, p2, Llyiahf/vczjk/yk1;

    iget-object p2, p0, Llyiahf/vczjk/g52;->OooOo00:Llyiahf/vczjk/vq;

    if-eqz p1, :cond_0

    new-instance p1, Llyiahf/vczjk/f52;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/f52;-><init>(Llyiahf/vczjk/g52;I)V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/vq;->execute(Ljava/lang/Runnable;)V

    return-void

    :cond_0
    new-instance p1, Llyiahf/vczjk/f52;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/f52;-><init>(Llyiahf/vczjk/g52;I)V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/vq;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 5

    const-string v0, "Releasing wakelock "

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOOo:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOoO:Llyiahf/vczjk/r09;

    if-eqz v2, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOoO:Llyiahf/vczjk/r09;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object v2, v2, Llyiahf/vczjk/bd9;->OooOOOO:Llyiahf/vczjk/hra;

    iget-object v3, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/hra;->OooO00o(Llyiahf/vczjk/jqa;)V

    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    if-eqz v2, :cond_1

    invoke-virtual {v2}, Landroid/os/PowerManager$WakeLock;->isHeld()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "for WorkSpec "

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v3, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V

    :cond_1
    monitor-exit v1

    return-void

    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0o(Z)V
    .locals 7

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "onExecuted "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, ", "

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/g52;->OooO0Oo()V

    const-class v0, Landroidx/work/impl/background/systemalarm/SystemAlarmService;

    iget v1, p0, Llyiahf/vczjk/g52;->OooOOO:I

    iget-object v3, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object v4, p0, Llyiahf/vczjk/g52;->OooOo0:Llyiahf/vczjk/wd;

    iget-object v5, p0, Llyiahf/vczjk/g52;->OooOOO0:Landroid/content/Context;

    if-eqz p1, :cond_0

    new-instance p1, Landroid/content/Intent;

    invoke-direct {p1, v5, v0}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v6, "ACTION_SCHEDULE_WORK"

    invoke-virtual {p1, v6}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {p1, v2}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    new-instance v2, Llyiahf/vczjk/bs;

    const/4 v6, 0x2

    invoke-direct {v2, v3, p1, v1, v6}, Llyiahf/vczjk/bs;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    invoke-virtual {v4, v2}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/g52;->OooOo0o:Z

    if-eqz p1, :cond_1

    new-instance p1, Landroid/content/Intent;

    invoke-direct {p1, v5, v0}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v0, "ACTION_CONSTRAINTS_CHANGED"

    invoke-virtual {p1, v0}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    new-instance v0, Llyiahf/vczjk/bs;

    const/4 v2, 0x2

    invoke-direct {v0, v3, p1, v1, v2}, Llyiahf/vczjk/bs;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    :cond_1
    return-void
.end method

.method public final OooO0o0()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOOO:Llyiahf/vczjk/jqa;

    iget-object v0, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOOO0:Landroid/content/Context;

    const-string v2, " ("

    invoke-static {v0, v2}, Llyiahf/vczjk/ii5;->OooOOOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    iget v3, p0, Llyiahf/vczjk/g52;->OooOOO:I

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, ")"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/fla;->OooO00o(Landroid/content/Context;Ljava/lang/String;)Landroid/os/PowerManager$WakeLock;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/g52;->OooOoOO:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Acquiring wakelock "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v4, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, "for WorkSpec "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOo0O:Landroid/os/PowerManager$WakeLock;

    invoke-virtual {v1}, Landroid/os/PowerManager$WakeLock;->acquire()V

    iget-object v1, p0, Llyiahf/vczjk/g52;->OooOOOo:Llyiahf/vczjk/bd9;

    iget-object v1, v1, Llyiahf/vczjk/bd9;->OooOOo0:Llyiahf/vczjk/oqa;

    iget-object v1, v1, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/bra;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/ara;

    move-result-object v1

    if-nez v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOo00:Llyiahf/vczjk/vq;

    new-instance v1, Llyiahf/vczjk/f52;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/f52;-><init>(Llyiahf/vczjk/g52;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/vq;->execute(Ljava/lang/Runnable;)V

    return-void

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/ara;->OooO0OO()Z

    move-result v3

    iput-boolean v3, p0, Llyiahf/vczjk/g52;->OooOo0o:Z

    if-nez v3, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    const-string v3, "No constraints for "

    invoke-virtual {v3, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOo00:Llyiahf/vczjk/vq;

    new-instance v1, Llyiahf/vczjk/f52;

    const/4 v2, 0x1

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/f52;-><init>(Llyiahf/vczjk/g52;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/vq;->execute(Ljava/lang/Runnable;)V

    return-void

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/g52;->OooOOo0:Llyiahf/vczjk/aqa;

    iget-object v2, p0, Llyiahf/vczjk/g52;->OooOoO0:Llyiahf/vczjk/qr1;

    invoke-static {v0, v1, v2, p0}, Llyiahf/vczjk/cqa;->OooO00o(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/qr1;Llyiahf/vczjk/pa6;)Llyiahf/vczjk/r09;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/g52;->OooOoO:Llyiahf/vczjk/r09;

    return-void
.end method
