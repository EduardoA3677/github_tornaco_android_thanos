.class public final synthetic Llyiahf/vczjk/f36;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/i36;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/i36;Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/f36;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    iput-object p2, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    const/4 v0, 0x1

    iget v1, p0, Llyiahf/vczjk/f36;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    iget-object v0, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    monitor-enter v1

    :try_start_0
    invoke-static {}, Lgithub/tornaco/android/thanos/db/n/NR;->builder()Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->pkgName(Ljava/lang/String;)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getTitle()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->title(Ljava/lang/String;)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getContent()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->content(Ljava/lang/String;)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->when(J)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->creationTime(J)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getType()I

    move-result v3

    invoke-virtual {v2, v3}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->type(I)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getChannelId()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, v0}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->channelId(Ljava/lang/String;)Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;

    move-result-object v0

    invoke-virtual {v1}, Llyiahf/vczjk/i36;->OooOo()Lgithub/tornaco/android/thanos/db/n/NRDb;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/db/n/NRDb;->nrDao()Lgithub/tornaco/android/thanos/db/n/NRDao;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/db/n/NR$NRBuilder;->build()Lgithub/tornaco/android/thanos/db/n/NR;

    move-result-object v0

    invoke-interface {v2, v0}, Lgithub/tornaco/android/thanos/db/n/NRDao;->insert(Lgithub/tornaco/android/thanos/db/n/NR;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    return-void

    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0

    :pswitch_0
    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    invoke-static {v1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    sget-object v2, Llyiahf/vczjk/l36;->OooO00o:Landroid/os/RemoteCallbackList;

    new-instance v2, Llyiahf/vczjk/k36;

    const/4 v3, 0x2

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/k36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V

    new-instance v1, Llyiahf/vczjk/y51;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void

    :pswitch_1
    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    iget-object v2, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/l36;->OooO00o:Landroid/os/RemoteCallbackList;

    new-instance v2, Llyiahf/vczjk/k36;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/k36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V

    new-instance v1, Llyiahf/vczjk/y51;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void

    :pswitch_2
    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    invoke-static {v1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    sget-object v2, Llyiahf/vczjk/l36;->OooO00o:Landroid/os/RemoteCallbackList;

    new-instance v2, Llyiahf/vczjk/k36;

    const/4 v3, 0x3

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/k36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V

    new-instance v3, Llyiahf/vczjk/y51;

    invoke-direct {v3, v2, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v2

    invoke-virtual {v3, v2}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->isAutoCancel()Z

    move-result v2

    if-eqz v2, :cond_0

    const-string v2, "Calling onRemoveNotificationRecordInternal since it is auto cancel."

    invoke-static {v2}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/k36;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/k36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V

    new-instance v1, Llyiahf/vczjk/y51;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :cond_0
    return-void

    :pswitch_3
    iget-object v1, p0, Llyiahf/vczjk/f36;->OooOOO:Llyiahf/vczjk/i36;

    iget-object v2, p0, Llyiahf/vczjk/f36;->OooOOOO:Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getType()I

    move-result v3

    if-nez v3, :cond_1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/i36;->OooOo0o(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V

    sget-object v3, Llyiahf/vczjk/l36;->OooO00o:Landroid/os/RemoteCallbackList;

    new-instance v3, Llyiahf/vczjk/k36;

    const/4 v4, 0x0

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/k36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;I)V

    new-instance v4, Llyiahf/vczjk/y51;

    invoke-direct {v4, v3, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v0

    invoke-virtual {v4, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :cond_1
    invoke-virtual {v1, v2}, Llyiahf/vczjk/i36;->OooOoO(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
