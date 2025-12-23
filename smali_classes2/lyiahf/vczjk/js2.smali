.class public final Llyiahf/vczjk/js2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/js2;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/js2;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/behavior/SwipeDismissBehavior;Landroid/view/View;Z)V
    .locals 0

    const/16 p3, 0x11

    iput p3, p0, Llyiahf/vczjk/js2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/v00;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Llyiahf/vczjk/js2;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method private final OooO00o()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jd9;

    iget-object v0, v0, Llyiahf/vczjk/jd9;->OooOOO0:Llyiahf/vczjk/oqa;

    iget-object v0, v0, Llyiahf/vczjk/oqa;->OooOOo0:Llyiahf/vczjk/n77;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    iget-object v2, v0, Llyiahf/vczjk/n77;->OooOO0O:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    invoke-virtual {v0, v1}, Llyiahf/vczjk/n77;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/wra;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    monitor-exit v2

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ara;->OooO0OO()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jd9;

    iget-object v1, v1, Llyiahf/vczjk/jd9;->OooOOOO:Ljava/lang/Object;

    monitor-enter v1

    :try_start_1
    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jd9;

    iget-object v2, v2, Llyiahf/vczjk/jd9;->OooOOo:Ljava/util/HashMap;

    invoke-static {v0}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v3

    invoke-virtual {v2, v3, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jd9;

    iget-object v3, v2, Llyiahf/vczjk/jd9;->OooOo00:Llyiahf/vczjk/aqa;

    iget-object v4, v2, Llyiahf/vczjk/jd9;->OooOOO:Llyiahf/vczjk/rqa;

    iget-object v4, v4, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    invoke-static {v3, v0, v4, v2}, Llyiahf/vczjk/cqa;->OooO00o(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/qr1;Llyiahf/vczjk/pa6;)Llyiahf/vczjk/r09;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jd9;

    iget-object v3, v3, Llyiahf/vczjk/jd9;->OooOOoo:Ljava/util/HashMap;

    invoke-static {v0}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v0

    invoke-virtual {v3, v0, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit v1

    return-void

    :catchall_1
    move-exception v0

    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    throw v0

    :cond_1
    return-void

    :goto_1
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw v0
.end method


# virtual methods
.method public final run()V
    .locals 5

    iget v0, p0, Llyiahf/vczjk/js2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tx9;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/tx9;->OooOOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ux9;

    iget-object v0, v0, Llyiahf/vczjk/ux9;->OooOOO0:Ljava/util/concurrent/PriorityBlockingQueue;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tx9;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/PriorityBlockingQueue;->remove(Ljava/lang/Object;)Z

    return-void

    :pswitch_0
    invoke-direct {p0}, Llyiahf/vczjk/js2;->OooO00o()V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/behavior/SwipeDismissBehavior;

    iget-object v0, v0, Lcom/google/android/material/behavior/SwipeDismissBehavior;->OooOOO0:Llyiahf/vczjk/iga;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/iga;->OooO0oo()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0, p0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    :cond_0
    return-void

    :pswitch_2
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Runnable;

    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vq;

    iget-object v0, v0, Llyiahf/vczjk/vq;->OooOOOo:Ljava/lang/Object;

    monitor-enter v0

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vq;

    invoke-virtual {v1}, Llyiahf/vczjk/vq;->OooO00o()V

    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v1

    :catchall_1
    move-exception v0

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vq;

    iget-object v1, v1, Llyiahf/vczjk/vq;->OooOOOo:Ljava/lang/Object;

    monitor-enter v1

    :try_start_2
    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/vq;

    invoke-virtual {v2}, Llyiahf/vczjk/vq;->OooO00o()V

    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    throw v0

    :catchall_2
    move-exception v0

    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    throw v0

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yp0;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/is2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yp0;->OooOooO(Llyiahf/vczjk/qr1;)V

    return-void

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ra3;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ra3;->accept(Ljava/lang/Object;)V

    return-void

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/u76;

    iget-object v0, v0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/f86;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p76;

    iget-object v0, v0, Llyiahf/vczjk/p76;->OooOOO0:Llyiahf/vczjk/j86;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    invoke-interface {v0, v1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    return-void

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p76;

    :try_start_4
    iget-object v1, v0, Llyiahf/vczjk/p76;->OooOOO0:Llyiahf/vczjk/j86;

    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/lang/Throwable;

    invoke-interface {v1, v2}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    iget-object v0, v0, Llyiahf/vczjk/p76;->OooOOOO:Llyiahf/vczjk/h88;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    return-void

    :catchall_3
    move-exception v1

    iget-object v0, v0, Llyiahf/vczjk/p76;->OooOOOO:Llyiahf/vczjk/h88;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    throw v1

    :pswitch_8
    const/4 v0, 0x0

    :cond_1
    :try_start_5
    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/Runnable;

    invoke-interface {v1}, Ljava/lang/Runnable;->run()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    goto :goto_0

    :catchall_4
    move-exception v1

    :try_start_6
    sget-object v2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-static {v1, v2}, Llyiahf/vczjk/u34;->OooOooO(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/az4;

    invoke-virtual {v1}, Llyiahf/vczjk/az4;->o0000()Ljava/lang/Runnable;

    move-result-object v1

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    iput-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    add-int/lit8 v0, v0, 0x1

    const/16 v1, 0x10

    if-lt v0, v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/az4;

    iget-object v2, v1, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-static {v2, v1}, Llyiahf/vczjk/dn8;->o0ooOOo(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/az4;

    iget-object v1, v0, Llyiahf/vczjk/az4;->OooOOOo:Llyiahf/vczjk/qr1;

    invoke-static {v1, v0, p0}, Llyiahf/vczjk/dn8;->o0ooOO0(Llyiahf/vczjk/qr1;Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    :goto_1
    return-void

    :catchall_5
    move-exception v0

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/az4;

    iget-object v2, v1, Llyiahf/vczjk/az4;->OooOOoo:Ljava/lang/Object;

    monitor-enter v2

    :try_start_7
    sget-object v3, Llyiahf/vczjk/az4;->OooOo00:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v3, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->decrementAndGet(Ljava/lang/Object;)I
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_6

    monitor-exit v2

    throw v0

    :catchall_6
    move-exception v0

    monitor-exit v2

    throw v0

    :pswitch_9
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mk4;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/Throwable;

    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    return-void

    :pswitch_a
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/i52;->OooO0o0:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Scheduling work "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ara;

    iget-object v4, v3, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i52;

    iget-object v0, v0, Llyiahf/vczjk/i52;->OooO00o:Llyiahf/vczjk/xj3;

    filled-new-array {v3}, [Llyiahf/vczjk/ara;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/xj3;->OooO0OO([Llyiahf/vczjk/ara;)V

    return-void

    :pswitch_b
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bh6;

    iget-object v0, v0, Llyiahf/vczjk/bh6;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cl6;

    if-eqz v0, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroid/graphics/Typeface;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cl6;->OooOOOO(Landroid/graphics/Typeface;)V

    :cond_3
    return-void

    :pswitch_c
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/k41;

    if-eqz v0, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v00;

    iget-object v1, v1, Llyiahf/vczjk/v00;->OooOO0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-interface {v2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    :cond_4
    return-void

    :pswitch_d
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rz;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Landroid/graphics/drawable/Drawable;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/rz;->invalidateDrawable(Landroid/graphics/drawable/Drawable;)V

    return-void

    :pswitch_e
    :try_start_8
    sget-object v0, Llyiahf/vczjk/j;->OooO0Oo:Ljava/lang/reflect/Method;
    :try_end_8
    .catch Ljava/lang/RuntimeException; {:try_start_8 .. :try_end_8} :catch_0
    .catchall {:try_start_8 .. :try_end_8} :catchall_7

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    if-eqz v0, :cond_5

    :try_start_9
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    const-string v4, "AppCompat recreation"

    filled-new-array {v1, v3, v4}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v2, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_5

    :catchall_7
    move-exception v0

    goto :goto_3

    :catch_0
    move-exception v0

    goto :goto_4

    :cond_5
    sget-object v0, Llyiahf/vczjk/j;->OooO0o0:Ljava/lang/reflect/Method;

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    filled-new-array {v1, v3}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v2, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_9
    .catch Ljava/lang/RuntimeException; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_7

    goto :goto_5

    :goto_3
    const-string v1, "ActivityRecreator"

    const-string v2, "Exception while invoking performStopActivity"

    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_5

    :goto_4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    const-class v2, Ljava/lang/RuntimeException;

    if-ne v1, v2, :cond_7

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Unable to stop"

    invoke-virtual {v1, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v1

    if-nez v1, :cond_6

    goto :goto_5

    :cond_6
    throw v0

    :cond_7
    :goto_5
    return-void

    :pswitch_f
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/app/Application;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/i;

    invoke-virtual {v0, v1}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    return-void

    :pswitch_10
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i;

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/i;->OooO00o:Ljava/lang/Object;

    return-void

    :pswitch_11
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/appcompat/widget/OooO0O0;

    iget-object v1, v0, Llyiahf/vczjk/j80;->OooOOOO:Llyiahf/vczjk/sg5;

    if-eqz v1, :cond_8

    iget-object v2, v1, Llyiahf/vczjk/sg5;->OooO0o0:Llyiahf/vczjk/qg5;

    if-eqz v2, :cond_8

    invoke-interface {v2, v1}, Llyiahf/vczjk/qg5;->OooOoO(Llyiahf/vczjk/sg5;)V

    :cond_8
    iget-object v1, v0, Llyiahf/vczjk/j80;->OooOo00:Llyiahf/vczjk/gi5;

    check-cast v1, Landroid/view/View;

    if-eqz v1, :cond_b

    invoke-virtual {v1}, Landroid/view/View;->getWindowToken()Landroid/os/IBinder;

    move-result-object v1

    if-eqz v1, :cond_b

    iget-object v1, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/oO000O0;

    invoke-virtual {v1}, Llyiahf/vczjk/wh5;->OooO0O0()Z

    move-result v2

    if-eqz v2, :cond_9

    goto :goto_6

    :cond_9
    iget-object v2, v1, Llyiahf/vczjk/wh5;->OooO0o:Landroid/view/View;

    if-nez v2, :cond_a

    goto :goto_7

    :cond_a
    const/4 v2, 0x0

    invoke-virtual {v1, v2, v2, v2, v2}, Llyiahf/vczjk/wh5;->OooO0o(IIZZ)V

    :goto_6
    iput-object v1, v0, Landroidx/appcompat/widget/OooO0O0;->Oooo000:Llyiahf/vczjk/oO000O0;

    :cond_b
    :goto_7
    const/4 v1, 0x0

    iput-object v1, v0, Landroidx/appcompat/widget/OooO0O0;->Oooo00o:Llyiahf/vczjk/js2;

    return-void

    :pswitch_12
    iget-object v0, p0, Llyiahf/vczjk/js2;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ks2;

    iget-object v1, v0, Llyiahf/vczjk/ks2;->direct:Llyiahf/vczjk/eg8;

    iget-object v2, p0, Llyiahf/vczjk/js2;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ns2;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ns2;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object v0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v0}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void

    :pswitch_data_0
    .packed-switch 0x0
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
