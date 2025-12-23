.class public Landroidx/work/impl/background/systemjob/SystemJobService;
.super Landroid/app/job/JobService;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gs2;


# static fields
.field public static final OooOOo0:Ljava/lang/String;


# instance fields
.field public final OooOOO:Ljava/util/HashMap;

.field public OooOOO0:Llyiahf/vczjk/oqa;

.field public final OooOOOO:Llyiahf/vczjk/fk7;

.field public OooOOOo:Llyiahf/vczjk/bp8;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "SystemJobService"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Landroid/app/job/JobService;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO:Ljava/util/HashMap;

    new-instance v0, Llyiahf/vczjk/fk7;

    invoke-direct {v0}, Llyiahf/vczjk/fk7;-><init>()V

    iput-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOO:Llyiahf/vczjk/fk7;

    return-void
.end method

.method public static OooO00o(Ljava/lang/String;)V
    .locals 3

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v1

    if-ne v0, v1, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot invoke "

    const-string v2, " on a background thread"

    invoke-static {v1, p0, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooO0O0(Landroid/app/job/JobParameters;)Llyiahf/vczjk/jqa;
    .locals 3

    const-string v0, "EXTRA_WORK_SPEC_ID"

    :try_start_0
    invoke-virtual {p0}, Landroid/app/job/JobParameters;->getExtras()Landroid/os/PersistableBundle;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/jqa;

    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "EXTRA_WORK_SPEC_GENERATION"

    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    move-result p0

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/jqa;-><init>(Ljava/lang/String;I)V
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/jqa;Z)V
    .locals 4

    const-string v0, "onExecuted"

    invoke-static {v0}, Landroidx/work/impl/background/systemjob/SystemJobService;->OooO00o(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v2, p1, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    const-string v3, " executed on JobScheduler"

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    sget-object v2, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/job/JobParameters;

    iget-object v1, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOO:Llyiahf/vczjk/fk7;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fk7;->OooOo0(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    if-eqz v0, :cond_0

    invoke-virtual {p0, v0, p2}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    :cond_0
    return-void
.end method

.method public final onCreate()V
    .locals 3

    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/oqa;->OoooOoo(Landroid/content/Context;)Llyiahf/vczjk/oqa;

    move-result-object v0

    iput-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO0:Llyiahf/vczjk/oqa;

    iget-object v1, v0, Llyiahf/vczjk/oqa;->OooOOo0:Llyiahf/vczjk/n77;

    new-instance v2, Llyiahf/vczjk/bp8;

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOOO:Llyiahf/vczjk/rqa;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/bp8;-><init>(Llyiahf/vczjk/n77;Llyiahf/vczjk/rqa;)V

    iput-object v2, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOo:Llyiahf/vczjk/bp8;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/n77;->OooO00o(Llyiahf/vczjk/gs2;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    invoke-virtual {p0}, Landroid/app/Service;->getApplication()Landroid/app/Application;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    const-class v2, Landroid/app/Application;

    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    const-string v2, "Could not find WorkManager instance; this may be because an auto-backup is in progress. Ignoring JobScheduler commands for now. Please make sure that you are initializing WorkManager if you have manually disabled WorkManagerInitializer."

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "WorkManager needs to be initialized via a ContentProvider#onCreate() or an Application#onCreate()."

    invoke-direct {v1, v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v1
.end method

.method public final onDestroy()V
    .locals 1

    invoke-super {p0}, Landroid/app/Service;->onDestroy()V

    iget-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO0:Llyiahf/vczjk/oqa;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOo0:Llyiahf/vczjk/n77;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/n77;->OooO0o0(Llyiahf/vczjk/gs2;)V

    :cond_0
    return-void
.end method

.method public final onStartJob(Landroid/app/job/JobParameters;)Z
    .locals 7

    const-string v0, "onStartJob"

    invoke-static {v0}, Landroidx/work/impl/background/systemjob/SystemJobService;->OooO00o(Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO0:Llyiahf/vczjk/oqa;

    const/4 v1, 0x1

    const/4 v2, 0x0

    sget-object v3, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    if-nez v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    const-string v4, "WorkManager is not initialized; requesting retry."

    invoke-virtual {v0, v3, v4}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {p0, p1, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    return v2

    :cond_0
    invoke-static {p1}, Landroidx/work/impl/background/systemjob/SystemJobService;->OooO0O0(Landroid/app/job/JobParameters;)Llyiahf/vczjk/jqa;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    const-string v0, "WorkSpec id not found!"

    invoke-virtual {p1, v3, v0}, Llyiahf/vczjk/o55;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    return v2

    :cond_1
    iget-object v4, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v4, v0}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v4, "Job is already being executed by SystemJobService: "

    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v3, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return v2

    :cond_2
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "onStartJob for "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v2, v3, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v4, v0, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    new-instance v3, Llyiahf/vczjk/xo8;

    const/16 v4, 0xa

    invoke-direct {v3, v4}, Llyiahf/vczjk/xo8;-><init>(I)V

    invoke-virtual {p1}, Landroid/app/job/JobParameters;->getTriggeredContentUris()[Landroid/net/Uri;

    move-result-object v4

    if-eqz v4, :cond_3

    invoke-virtual {p1}, Landroid/app/job/JobParameters;->getTriggeredContentUris()[Landroid/net/Uri;

    move-result-object v4

    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    iput-object v4, v3, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    :cond_3
    invoke-virtual {p1}, Landroid/app/job/JobParameters;->getTriggeredContentAuthorities()[Ljava/lang/String;

    move-result-object v4

    if-eqz v4, :cond_4

    invoke-virtual {p1}, Landroid/app/job/JobParameters;->getTriggeredContentAuthorities()[Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    iput-object v4, v3, Llyiahf/vczjk/xo8;->OooOOO0:Ljava/lang/Object;

    :cond_4
    const/16 v4, 0x1c

    if-lt v2, v4, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/wo;->OooOO0O(Landroid/app/job/JobParameters;)V

    :cond_5
    iget-object p1, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOo:Llyiahf/vczjk/bp8;

    iget-object v2, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOO:Llyiahf/vczjk/fk7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fk7;->OooOo0O(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/oOO0;

    const/16 v4, 0x11

    invoke-direct {v2, p1, v0, v4, v3}, Llyiahf/vczjk/oOO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rqa;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/rqa;->OooO00o(Ljava/lang/Runnable;)V

    return v1
.end method

.method public final onStopJob(Landroid/app/job/JobParameters;)Z
    .locals 6

    const-string v0, "onStopJob"

    invoke-static {v0}, Landroidx/work/impl/background/systemjob/SystemJobService;->OooO00o(Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO0:Llyiahf/vczjk/oqa;

    const/4 v1, 0x1

    if-nez v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    const-string v2, "WorkManager is not initialized; requesting retry."

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    return v1

    :cond_0
    invoke-static {p1}, Landroidx/work/impl/background/systemjob/SystemJobService;->OooO0O0(Landroid/app/job/JobParameters;)Llyiahf/vczjk/jqa;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    const-string v1, "WorkSpec id not found!"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/o55;->OooO0o(Ljava/lang/String;Ljava/lang/String;)V

    const/4 p1, 0x0

    return p1

    :cond_1
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    sget-object v3, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOo0:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "onStopJob for "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v2, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v2, v0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v2, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOO:Llyiahf/vczjk/fk7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fk7;->OooOo0(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object v2

    if-eqz v2, :cond_3

    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1f

    if-lt v3, v4, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/yo;->OooO0OO(Landroid/app/job/JobParameters;)I

    move-result p1

    goto :goto_0

    :cond_2
    const/16 p1, -0x200

    :goto_0
    iget-object v3, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOOo:Llyiahf/vczjk/bp8;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v3, v2, p1}, Llyiahf/vczjk/bp8;->OooO00o(Llyiahf/vczjk/g29;I)V

    :cond_3
    iget-object p1, p0, Landroidx/work/impl/background/systemjob/SystemJobService;->OooOOO0:Llyiahf/vczjk/oqa;

    iget-object p1, p1, Llyiahf/vczjk/oqa;->OooOOo0:Llyiahf/vczjk/n77;

    iget-object v0, v0, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    iget-object p1, p1, Llyiahf/vczjk/n77;->OooO:Ljava/util/HashSet;

    invoke-virtual {p1, v0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p1

    monitor-exit v2

    xor-int/2addr p1, v1

    return p1

    :catchall_0
    move-exception p1

    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method
