.class public final Llyiahf/vczjk/vn8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uma;


# static fields
.field public static volatile OooO0OO:Llyiahf/vczjk/vn8;

.field public static final OooO0Oo:Ljava/util/concurrent/locks/ReentrantLock;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tn8;

.field public final OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/util/concurrent/locks/ReentrantLock;

    invoke-direct {v0}, Ljava/util/concurrent/locks/ReentrantLock;-><init>()V

    sput-object v0, Llyiahf/vczjk/vn8;->OooO0Oo:Ljava/util/concurrent/locks/ReentrantLock;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tn8;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vn8;->OooO00o:Llyiahf/vczjk/tn8;

    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/vn8;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    if-eqz p1, :cond_0

    new-instance v0, Llyiahf/vczjk/fk7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/fk7;-><init>(Ljava/lang/Object;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tn8;->OooO0Oo(Llyiahf/vczjk/fk7;)V

    :cond_0
    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/content/Context;Ljava/util/concurrent/Executor;Llyiahf/vczjk/ol1;)V
    .locals 8

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p1, Landroid/app/Activity;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Landroid/app/Activity;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-eqz p1, :cond_c

    sget-object v2, Llyiahf/vczjk/vn8;->OooO0Oo:Ljava/util/concurrent/locks/ReentrantLock;

    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    :try_start_0
    iget-object v3, p0, Llyiahf/vczjk/vn8;->OooO00o:Llyiahf/vczjk/tn8;

    if-nez v3, :cond_1

    new-instance p1, Llyiahf/vczjk/voa;

    invoke-direct {p1, v0}, Llyiahf/vczjk/voa;-><init>(Ljava/util/List;)V

    invoke-interface {p3, p1}, Llyiahf/vczjk/ol1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    return-void

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :cond_1
    iget-object v4, p0, Llyiahf/vczjk/vn8;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    const/4 v5, 0x0

    if-eqz v4, :cond_2

    :try_start_1
    invoke-virtual {v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_4

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/un8;

    iget-object v7, v7, Llyiahf/vczjk/un8;->OooO00o:Landroid/app/Activity;

    invoke-virtual {v7, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_3

    const/4 v5, 0x1

    :cond_4
    :goto_1
    new-instance v6, Llyiahf/vczjk/un8;

    invoke-direct {v6, p1, p2, p3}, Llyiahf/vczjk/un8;-><init>(Landroid/app/Activity;Ljava/util/concurrent/Executor;Llyiahf/vczjk/ol1;)V

    invoke-virtual {v4, v6}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    if-nez v5, :cond_7

    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object p2

    if-eqz p2, :cond_5

    invoke-virtual {p2}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    move-result-object p2

    if-eqz p2, :cond_5

    iget-object v1, p2, Landroid/view/WindowManager$LayoutParams;->token:Landroid/os/IBinder;

    :cond_5
    if-eqz v1, :cond_6

    invoke-virtual {v3, v1, p1}, Llyiahf/vczjk/tn8;->OooO0OO(Landroid/os/IBinder;Landroid/app/Activity;)V

    goto :goto_3

    :cond_6
    new-instance p2, Llyiahf/vczjk/sn8;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/sn8;-><init>(Llyiahf/vczjk/tn8;Landroid/app/Activity;)V

    invoke-virtual {p1}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1, p2}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    goto :goto_3

    :cond_7
    invoke-virtual {v4}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_8
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/un8;

    iget-object v4, v4, Llyiahf/vczjk/un8;->OooO00o:Landroid/app/Activity;

    invoke-virtual {p1, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_8

    goto :goto_2

    :cond_9
    move-object v3, v1

    :goto_2
    check-cast v3, Llyiahf/vczjk/un8;

    if-eqz v3, :cond_a

    iget-object v1, v3, Llyiahf/vczjk/un8;->OooO0Oo:Llyiahf/vczjk/voa;

    :cond_a
    if-eqz v1, :cond_b

    iput-object v1, v6, Llyiahf/vczjk/un8;->OooO0Oo:Llyiahf/vczjk/voa;

    new-instance p1, Llyiahf/vczjk/tm4;

    const/16 p2, 0x1b

    invoke-direct {p1, p2, v6, v1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p2, v6, Llyiahf/vczjk/un8;->OooO0O0:Ljava/util/concurrent/Executor;

    invoke-interface {p2, p1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_b
    :goto_3
    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_5

    :goto_4
    invoke-virtual {v2}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p1

    :cond_c
    :goto_5
    if-nez v1, :cond_d

    new-instance p1, Llyiahf/vczjk/voa;

    invoke-direct {p1, v0}, Llyiahf/vczjk/voa;-><init>(Ljava/util/List;)V

    invoke-interface {p3, p1}, Llyiahf/vczjk/ol1;->accept(Ljava/lang/Object;)V

    :cond_d
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/ol1;)V
    .locals 5

    const-string v0, "callback"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/vn8;->OooO0Oo:Ljava/util/concurrent/locks/ReentrantLock;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/vn8;->OooO00o:Llyiahf/vczjk/tn8;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v1, :cond_0

    monitor-exit v0

    return-void

    :cond_0
    :try_start_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/vn8;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_1
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/un8;

    iget-object v4, v3, Llyiahf/vczjk/un8;->OooO0OO:Llyiahf/vczjk/ol1;

    if-ne v4, p1, :cond_1

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/vn8;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->removeAll(Ljava/util/Collection;)Z

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_7

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/un8;

    iget-object v1, v1, Llyiahf/vczjk/un8;->OooO00o:Landroid/app/Activity;

    iget-object v2, p0, Llyiahf/vczjk/vn8;->OooO0O0:Ljava/util/concurrent/CopyOnWriteArrayList;

    if-eqz v2, :cond_4

    invoke-virtual {v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/un8;

    iget-object v3, v3, Llyiahf/vczjk/un8;->OooO00o:Landroid/app/Activity;

    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    goto :goto_1

    :cond_6
    :goto_2
    iget-object v2, p0, Llyiahf/vczjk/vn8;->OooO00o:Llyiahf/vczjk/tn8;

    if-eqz v2, :cond_3

    invoke-virtual {v2, v1}, Llyiahf/vczjk/tn8;->OooO0O0(Landroid/app/Activity;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :cond_7
    monitor-exit v0

    return-void

    :goto_3
    monitor-exit v0

    throw p1
.end method
