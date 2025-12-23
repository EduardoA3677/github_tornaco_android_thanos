.class public final synthetic Llyiahf/vczjk/oOOO0OOO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a;Ljava/lang/String;Ljava/lang/String;Lgithub/tornaco/android/thanos/core/process/ProcessRecord;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo0:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/e86;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/tr5;Llyiahf/vczjk/mo0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    iget v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le3;

    iget-object v2, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/tr5;

    iget-object v3, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/mo0;

    iget-object v4, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/e86;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/ll6;->OooOO0()Z

    move-result v4

    if-eqz v4, :cond_0

    :try_start_0
    const-string v5, "label"

    invoke-static {v0, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :cond_0
    :try_start_1
    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/ee6;->OooO00o:Llyiahf/vczjk/yd6;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tr5;->OooOO0(Ljava/lang/Object;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/mo0;->OooO00o(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    :try_start_2
    new-instance v1, Llyiahf/vczjk/xd6;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xd6;-><init>(Ljava/lang/Throwable;)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/tr5;->OooOO0(Ljava/lang/Object;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/mo0;->OooO0O0(Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_0
    if-eqz v4, :cond_1

    invoke-static {}, Landroid/os/Trace;->endSection()V

    :cond_1
    return-void

    :catchall_1
    move-exception v0

    if-eqz v4, :cond_2

    invoke-static {}, Landroid/os/Trace;->endSection()V

    :cond_2
    throw v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a;

    iget-object v1, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    if-nez v1, :cond_3

    goto :goto_2

    :cond_3
    iget-object v0, v0, Llyiahf/vczjk/a;->OoooOOo:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    if-nez v2, :cond_4

    const/4 v2, 0x0

    goto :goto_1

    :cond_4
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    add-int/lit8 v2, v2, 0x1

    :goto_1
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-virtual {v0, v1, v3}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x6

    if-le v2, v0, :cond_5

    goto :goto_2

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/process/ProcessRecord;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "8.6-3354368-thanox@tornaco:f919506c-e8fd-4a35-b88e-e193d2725db5\t"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOO:Ljava/lang/String;

    const-string v4, "\t"

    invoke-static {v2, v3, v4, v1, v4}, Llyiahf/vczjk/q99;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/oOOO0OOO;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "onApplicationCrashing: "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/oOO0OO;

    const/4 v4, 0x0

    invoke-direct {v2, v3, v1, v0, v4}, Llyiahf/vczjk/oOO0OO;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v0, Llyiahf/vczjk/y51;

    const/4 v1, 0x1

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :goto_2
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
