.class public final synthetic Llyiahf/vczjk/mra;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/wra;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/wra;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/mra;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/mra;->OooOOO:Llyiahf/vczjk/wra;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/mra;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/mra;->OooOOO:Llyiahf/vczjk/wra;

    iget-object v1, v0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    iget-object v2, v0, Llyiahf/vczjk/wra;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/bra;->OooO0o(Ljava/lang/String;)Llyiahf/vczjk/lqa;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    if-ne v1, v3, :cond_0

    sget-object v1, Llyiahf/vczjk/lqa;->OooOOO:Llyiahf/vczjk/lqa;

    iget-object v0, v0, Llyiahf/vczjk/wra;->OooO:Llyiahf/vczjk/bra;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/bra;->OooOO0o(Llyiahf/vczjk/lqa;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/bra;->OooO00o:Landroidx/work/impl/WorkDatabase_Impl;

    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->assertNotSuspendingTransaction()V

    iget-object v3, v0, Llyiahf/vczjk/bra;->OooO0oo:Llyiahf/vczjk/qw7;

    invoke-virtual {v3}, Llyiahf/vczjk/yd7;->OooO00o()Llyiahf/vczjk/la9;

    move-result-object v4

    const/4 v5, 0x1

    invoke-interface {v4, v5, v2}, Llyiahf/vczjk/ha9;->OooOOO0(ILjava/lang/String;)V

    :try_start_0
    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->beginTransaction()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    invoke-interface {v4}, Llyiahf/vczjk/la9;->OooOOOo()I

    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->endTransaction()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    const/16 v1, -0x100

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/bra;->OooOOO0(ILjava/lang/String;)V

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_0

    :catchall_1
    move-exception v0

    :try_start_3
    invoke-virtual {v1}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_0
    invoke-virtual {v3, v4}, Llyiahf/vczjk/yd7;->OooO0o(Llyiahf/vczjk/la9;)V

    throw v0

    :cond_0
    const/4 v5, 0x0

    :goto_1
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/mra;->OooOOO:Llyiahf/vczjk/wra;

    iget-object v1, v0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget-object v2, v1, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    sget-object v3, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    iget-object v4, v1, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    if-eq v2, v3, :cond_1

    sget-object v0, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " is not in ENQUEUED state. Nothing more to do"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_2

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/ara;->OooO0Oo()Z

    move-result v2

    if-nez v2, :cond_2

    iget-object v2, v1, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    if-ne v2, v3, :cond_3

    iget v2, v1, Llyiahf/vczjk/ara;->OooOO0O:I

    if-lez v2, :cond_3

    :cond_2
    iget-object v0, v0, Llyiahf/vczjk/wra;->OooO0o:Llyiahf/vczjk/vp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    invoke-virtual {v1}, Llyiahf/vczjk/ara;->OooO00o()J

    move-result-wide v0

    cmp-long v0, v2, v0

    if-gez v0, :cond_3

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Delaying execution for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " because it is being executed before schedule."

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_2

    :cond_3
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_2
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
