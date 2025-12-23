.class public final Llyiahf/vczjk/ui6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/nk6;

.field public final OooO0O0:Llyiahf/vczjk/o55;

.field public final OooO0OO:Llyiahf/vczjk/n62;

.field public final OooO0Oo:Llyiahf/vczjk/n62;

.field public final OooO0o0:Llyiahf/vczjk/f43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nk6;Llyiahf/vczjk/o55;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ui6;->OooO00o:Llyiahf/vczjk/nk6;

    iput-object p2, p0, Llyiahf/vczjk/ui6;->OooO0O0:Llyiahf/vczjk/o55;

    new-instance p1, Llyiahf/vczjk/n62;

    const/16 p2, 0xa

    invoke-direct {p1, p2}, Llyiahf/vczjk/n62;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/ui6;->OooO0OO:Llyiahf/vczjk/n62;

    new-instance p1, Llyiahf/vczjk/n62;

    invoke-direct {p1, p2}, Llyiahf/vczjk/n62;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/ui6;->OooO0Oo:Llyiahf/vczjk/n62;

    new-instance p1, Llyiahf/vczjk/si6;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p0}, Llyiahf/vczjk/si6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooOOOo(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/f43;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ui6;->OooO0o0:Llyiahf/vczjk/f43;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/ui6;Llyiahf/vczjk/c46;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 12

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p2, Llyiahf/vczjk/ti6;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ti6;

    iget v1, v0, Llyiahf/vczjk/ti6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ti6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ti6;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ti6;-><init>(Llyiahf/vczjk/ui6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ti6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ti6;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_3

    if-ne v2, v3, :cond_2

    iget-object p0, v0, Llyiahf/vczjk/ti6;->L$1:Ljava/lang/Object;

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/c46;

    iget-object p0, v0, Llyiahf/vczjk/ti6;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/ui6;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_1
    move-object v6, p0

    goto :goto_1

    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/ti6;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ti6;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/ti6;->label:I

    iget-object p2, p0, Llyiahf/vczjk/ui6;->OooO00o:Llyiahf/vczjk/nk6;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/nk6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_1

    return-object v1

    :goto_1
    check-cast p2, Llyiahf/vczjk/c46;

    if-eq p2, p1, :cond_d

    new-instance v4, Llyiahf/vczjk/da;

    const-string v9, "invalidate()V"

    const/4 v10, 0x0

    const/4 v5, 0x0

    const-class v7, Llyiahf/vczjk/ui6;

    const-string v8, "invalidate"

    const/16 v11, 0xa

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p0, p2, Llyiahf/vczjk/c46;->OooO00o:Llyiahf/vczjk/hl1;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-boolean v0, p0, Llyiahf/vczjk/hl1;->OooOOO:Z

    if-eqz v0, :cond_4

    invoke-virtual {v4}, Llyiahf/vczjk/da;->OooO00o()Ljava/lang/Object;

    goto :goto_3

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Ljava/util/concurrent/locks/ReentrantLock;

    :try_start_0
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    iget-boolean v0, p0, Llyiahf/vczjk/hl1;->OooOOO:Z

    if-eqz v0, :cond_5

    goto :goto_2

    :cond_5
    iget-object p0, p0, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast p0, Ljava/util/ArrayList;

    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    const/4 v3, 0x0

    :goto_2
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    if-eqz v3, :cond_6

    invoke-virtual {v4}, Llyiahf/vczjk/da;->OooO00o()Ljava/lang/Object;

    :cond_6
    :goto_3
    if-eqz p1, :cond_7

    new-instance v4, Llyiahf/vczjk/da;

    const-string v9, "invalidate()V"

    const/4 v10, 0x0

    const/4 v5, 0x0

    const-class v7, Llyiahf/vczjk/ui6;

    const-string v8, "invalidate"

    const/16 v11, 0xb

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    iget-object p0, p1, Llyiahf/vczjk/c46;->OooO00o:Llyiahf/vczjk/hl1;

    iget-object v0, p0, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Ljava/util/concurrent/locks/ReentrantLock;

    :try_start_1
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    iget-object p0, p0, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast p0, Ljava/util/ArrayList;

    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    goto :goto_4

    :catchall_0
    move-exception v0

    move-object p0, v0

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p0

    :cond_7
    :goto_4
    const/4 p0, 0x0

    const-string v0, "message"

    const/4 v1, 0x3

    const-string v2, "Paging"

    if-eqz p1, :cond_b

    iget-object v3, p1, Llyiahf/vczjk/c46;->OooO00o:Llyiahf/vczjk/hl1;

    iget-boolean v4, v3, Llyiahf/vczjk/hl1;->OooOOO:Z

    const/4 v5, 0x0

    if-eqz v4, :cond_8

    goto :goto_6

    :cond_8
    iget-object v4, v3, Llyiahf/vczjk/hl1;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Ljava/util/concurrent/locks/ReentrantLock;

    :try_start_2
    invoke-virtual {v4}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    iget-boolean v6, v3, Llyiahf/vczjk/hl1;->OooOOO:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    if-eqz v6, :cond_9

    invoke-virtual {v4}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    goto :goto_6

    :cond_9
    const/4 v5, 0x1

    :try_start_3
    iput-boolean v5, v3, Llyiahf/vczjk/hl1;->OooOOO:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    iget-object v3, v3, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Ljava/util/ArrayList;

    :try_start_4
    invoke-static {v3}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v6

    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    invoke-virtual {v4}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_5
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_a

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/le3;

    const-string v6, "it"

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    goto :goto_5

    :cond_a
    :goto_6
    if-eqz v5, :cond_b

    sget-object v3, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v3, :cond_b

    invoke-static {v2, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v3

    if-eqz v3, :cond_b

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Invalidated PagingSource "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2, p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_7

    :catchall_1
    move-exception v0

    move-object p0, v0

    invoke-virtual {v4}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p0

    :cond_b
    :goto_7
    sget-object p1, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz p1, :cond_c

    invoke-static {v2, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result p1

    if-eqz p1, :cond_c

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v1, "Generated new PagingSource "

    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2, p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_c
    return-object p2

    :catchall_2
    move-exception v0

    move-object p0, v0

    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p0

    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "An instance of PagingSource was re-used when Pager expected to create a new\ninstance. Ensure that the pagingSourceFactory passed to Pager always returns a\nnew instance of PagingSource."

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method
