.class public final Llyiahf/vczjk/p96;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j01;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/we4;

.field public final OooO0O0:Llyiahf/vczjk/zp6;

.field public final OooO0OO:Llyiahf/vczjk/j96;

.field public final OooO0Oo:Llyiahf/vczjk/yp8;

.field public final OooO0o:Llyiahf/vczjk/tqa;

.field public final OooO0o0:Llyiahf/vczjk/l96;

.field public final OooO0oO:Llyiahf/vczjk/mt5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/zp6;Llyiahf/vczjk/j96;Llyiahf/vczjk/yp8;Llyiahf/vczjk/l96;)V
    .locals 1

    const-string v0, "fileSystem"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "path"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "coordinator"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    iput-object p2, p0, Llyiahf/vczjk/p96;->OooO0O0:Llyiahf/vczjk/zp6;

    iput-object p3, p0, Llyiahf/vczjk/p96;->OooO0OO:Llyiahf/vczjk/j96;

    iput-object p4, p0, Llyiahf/vczjk/p96;->OooO0Oo:Llyiahf/vczjk/yp8;

    iput-object p5, p0, Llyiahf/vczjk/p96;->OooO0o0:Llyiahf/vczjk/l96;

    new-instance p1, Llyiahf/vczjk/tqa;

    const/4 p2, 0x6

    invoke-direct {p1, p2}, Llyiahf/vczjk/tqa;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/p96;->OooO0o:Llyiahf/vczjk/tqa;

    new-instance p1, Llyiahf/vczjk/mt5;

    invoke-direct {p1}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p96;->OooO0oO:Llyiahf/vczjk/mt5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v59;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 8

    instance-of v0, p2, Llyiahf/vczjk/n96;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/n96;

    iget v1, v0, Llyiahf/vczjk/n96;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/n96;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/n96;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/n96;-><init>(Llyiahf/vczjk/p96;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/n96;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/n96;->label:I

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v4, :cond_1

    iget-boolean p1, v0, Llyiahf/vczjk/n96;->Z$0:Z

    iget-object v1, v0, Llyiahf/vczjk/n96;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/j01;

    iget-object v0, v0, Llyiahf/vczjk/n96;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p96;

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p2

    goto :goto_3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO0o:Llyiahf/vczjk/tqa;

    iget-object p2, p2, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast p2, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result p2

    if-nez p2, :cond_7

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO0oO:Llyiahf/vczjk/mt5;

    invoke-virtual {p2}, Llyiahf/vczjk/mt5;->OooO0o()Z

    move-result p2

    :try_start_1
    new-instance v2, Llyiahf/vczjk/i96;

    iget-object v5, p0, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    iget-object v6, p0, Llyiahf/vczjk/p96;->OooO0O0:Llyiahf/vczjk/zp6;

    iget-object v7, p0, Llyiahf/vczjk/p96;->OooO0OO:Llyiahf/vczjk/j96;

    invoke-direct {v2, v5, v6, v7}, Llyiahf/vczjk/i96;-><init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/zp6;Llyiahf/vczjk/j96;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    :try_start_2
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    iput-object p0, v0, Llyiahf/vczjk/n96;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/n96;->L$1:Ljava/lang/Object;

    iput-boolean p2, v0, Llyiahf/vczjk/n96;->Z$0:Z

    iput v4, v0, Llyiahf/vczjk/n96;->label:I

    invoke-virtual {p1, v2, v5, v0}, Llyiahf/vczjk/v59;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    move v0, p2

    move-object p2, p1

    move p1, v0

    move-object v0, p0

    move-object v1, v2

    :goto_1
    :try_start_3
    invoke-interface {v1}, Llyiahf/vczjk/j01;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    move-object v1, v3

    goto :goto_2

    :catchall_1
    move-exception v1

    :goto_2
    if-nez v1, :cond_5

    if-eqz p1, :cond_4

    iget-object p1, v0, Llyiahf/vczjk/p96;->OooO0oO:Llyiahf/vczjk/mt5;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    :cond_4
    return-object p2

    :cond_5
    :try_start_4
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception p2

    goto :goto_6

    :catchall_3
    move-exception p1

    move v0, p2

    move-object p2, p1

    move p1, v0

    move-object v0, p0

    move-object v1, v2

    :goto_3
    :try_start_5
    invoke-interface {v1}, Llyiahf/vczjk/j01;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    goto :goto_4

    :catchall_4
    move-exception v1

    :try_start_6
    invoke-static {p2, v1}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_4
    throw p2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    :goto_5
    move v0, p2

    move-object p2, p1

    move p1, v0

    move-object v0, p0

    goto :goto_6

    :catchall_5
    move-exception p1

    goto :goto_5

    :goto_6
    if-eqz p1, :cond_6

    iget-object p1, v0, Llyiahf/vczjk/p96;->OooO0oO:Llyiahf/vczjk/mt5;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    :cond_6
    throw p2

    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "StorageConnection has already been disposed."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/iz1;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    const-string v0, ".tmp"

    instance-of v1, p2, Llyiahf/vczjk/o96;

    if-eqz v1, :cond_0

    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/o96;

    iget v2, v1, Llyiahf/vczjk/o96;->label:I

    const/high16 v3, -0x80000000

    and-int v4, v2, v3

    if-eqz v4, :cond_0

    sub-int/2addr v2, v3

    iput v2, v1, Llyiahf/vczjk/o96;->label:I

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/o96;

    invoke-direct {v1, p0, p2}, Llyiahf/vczjk/o96;-><init>(Llyiahf/vczjk/p96;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v1, Llyiahf/vczjk/o96;->result:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v3, v1, Llyiahf/vczjk/o96;->label:I

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eqz v3, :cond_3

    if-eq v3, v5, :cond_2

    if-ne v3, v4, :cond_1

    iget-object p1, v1, Llyiahf/vczjk/o96;->L$3:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/j01;

    iget-object v0, v1, Llyiahf/vczjk/o96;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zp6;

    iget-object v2, v1, Llyiahf/vczjk/o96;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v1, v1, Llyiahf/vczjk/o96;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/p96;

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_3

    :catchall_0
    move-exception p2

    goto/16 :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v1, Llyiahf/vczjk/o96;->L$3:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jt5;

    iget-object v3, v1, Llyiahf/vczjk/o96;->L$2:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/zp6;

    iget-object v5, v1, Llyiahf/vczjk/o96;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/ze3;

    iget-object v7, v1, Llyiahf/vczjk/o96;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/p96;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p2, p1

    move-object p1, v5

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO0o:Llyiahf/vczjk/tqa;

    iget-object p2, p2, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast p2, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result p2

    if-nez p2, :cond_a

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO0O0:Llyiahf/vczjk/zp6;

    invoke-virtual {p2}, Llyiahf/vczjk/zp6;->OooO0OO()Llyiahf/vczjk/zp6;

    move-result-object v3

    if-eqz v3, :cond_9

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    invoke-virtual {p2, v3}, Llyiahf/vczjk/ez2;->OooO00o(Llyiahf/vczjk/zp6;)V

    iput-object p0, v1, Llyiahf/vczjk/o96;->L$0:Ljava/lang/Object;

    iput-object p1, v1, Llyiahf/vczjk/o96;->L$1:Ljava/lang/Object;

    iput-object v3, v1, Llyiahf/vczjk/o96;->L$2:Ljava/lang/Object;

    iget-object p2, p0, Llyiahf/vczjk/p96;->OooO0oO:Llyiahf/vczjk/mt5;

    iput-object p2, v1, Llyiahf/vczjk/o96;->L$3:Ljava/lang/Object;

    iput v5, v1, Llyiahf/vczjk/o96;->label:I

    invoke-virtual {p2, v1}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v2, :cond_4

    goto :goto_2

    :cond_4
    move-object v7, p0

    :goto_1
    :try_start_1
    iget-object v5, v7, Llyiahf/vczjk/p96;->OooO0O0:Llyiahf/vczjk/zp6;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    iget-object v8, v7, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    :try_start_2
    invoke-virtual {v5}, Llyiahf/vczjk/zp6;->OooO0O0()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v5, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zp6;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/zp6;

    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_5

    :try_start_3
    invoke-virtual {v8, v0}, Llyiahf/vczjk/we4;->OooO0OO(Llyiahf/vczjk/zp6;)V

    new-instance v3, Llyiahf/vczjk/r96;

    iget-object v5, v7, Llyiahf/vczjk/p96;->OooO0OO:Llyiahf/vczjk/j96;

    invoke-direct {v3, v8, v0, v5}, Llyiahf/vczjk/i96;-><init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/zp6;Llyiahf/vczjk/j96;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_5

    :try_start_4
    iput-object v7, v1, Llyiahf/vczjk/o96;->L$0:Ljava/lang/Object;

    iput-object p2, v1, Llyiahf/vczjk/o96;->L$1:Ljava/lang/Object;

    iput-object v0, v1, Llyiahf/vczjk/o96;->L$2:Ljava/lang/Object;

    iput-object v3, v1, Llyiahf/vczjk/o96;->L$3:Ljava/lang/Object;

    iput v4, v1, Llyiahf/vczjk/o96;->label:I

    invoke-interface {p1, v3, v1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    if-ne p1, v2, :cond_5

    :goto_2
    return-object v2

    :cond_5
    move-object v2, p2

    move-object p1, v3

    move-object v1, v7

    :goto_3
    :try_start_5
    invoke-interface {p1}, Llyiahf/vczjk/j01;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    move-object p1, v6

    goto :goto_4

    :catchall_1
    move-exception p1

    :goto_4
    if-nez p1, :cond_7

    :try_start_6
    iget-object p1, v1, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ez2;->OooO0o0(Llyiahf/vczjk/zp6;)Z

    move-result p1

    if-eqz p1, :cond_6

    iget-object p1, v1, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    iget-object p2, v1, Llyiahf/vczjk/p96;->OooO0O0:Llyiahf/vczjk/zp6;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/we4;->OooOO0o(Llyiahf/vczjk/zp6;Llyiahf/vczjk/zp6;)V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    goto :goto_5

    :catchall_2
    move-exception p1

    move-object p2, v2

    goto :goto_9

    :catch_0
    move-exception p1

    move-object v7, v1

    move-object p2, v2

    goto :goto_8

    :cond_6
    :goto_5
    invoke-interface {v2, v6}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_7
    :try_start_7
    throw p1
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    :catchall_3
    move-exception p1

    move-object v2, p2

    move-object v1, v7

    move-object p2, p1

    move-object p1, v3

    :goto_6
    :try_start_8
    invoke-interface {p1}, Llyiahf/vczjk/j01;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    goto :goto_7

    :catchall_4
    move-exception p1

    :try_start_9
    invoke-static {p2, p1}, Llyiahf/vczjk/cp7;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    :goto_7
    throw p2
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    :catchall_5
    move-exception p1

    goto :goto_9

    :catch_1
    move-exception p1

    :goto_8
    :try_start_a
    iget-object v1, v7, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ez2;->OooO0o0(Llyiahf/vczjk/zp6;)Z

    move-result v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    if-eqz v1, :cond_8

    :try_start_b
    iget-object v1, v7, Llyiahf/vczjk/p96;->OooO00o:Llyiahf/vczjk/we4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/we4;->OooO0OO(Llyiahf/vczjk/zp6;)V
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_2
    .catchall {:try_start_b .. :try_end_b} :catchall_5

    :catch_2
    :cond_8
    :try_start_c
    throw p1
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_5

    :goto_9
    invoke-interface {p2, v6}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "must have a parent path"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "StorageConnection has already been disposed."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final close()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/p96;->OooO0o:Llyiahf/vczjk/tqa;

    iget-object v0, v0, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    iget-object v0, p0, Llyiahf/vczjk/p96;->OooO0o0:Llyiahf/vczjk/l96;

    invoke-virtual {v0}, Llyiahf/vczjk/l96;->OooO00o()Ljava/lang/Object;

    return-void
.end method
