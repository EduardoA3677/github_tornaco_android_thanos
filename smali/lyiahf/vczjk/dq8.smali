.class public final Llyiahf/vczjk/dq8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/gq8;

.field public final OooO0O0:Z

.field public final OooO0OO:Llyiahf/vczjk/mt5;

.field public OooO0Oo:Llyiahf/vczjk/v74;

.field public OooO0o0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gq8;Z)V
    .locals 1

    const-string v0, "singleRunner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dq8;->OooO00o:Llyiahf/vczjk/gq8;

    iput-boolean p2, p0, Llyiahf/vczjk/dq8;->OooO0O0:Z

    new-instance p1, Llyiahf/vczjk/mt5;

    invoke-direct {p1}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dq8;->OooO0OO:Llyiahf/vczjk/mt5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v74;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/bq8;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/bq8;

    iget v1, v0, Llyiahf/vczjk/bq8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/bq8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/bq8;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/bq8;-><init>(Llyiahf/vczjk/dq8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/bq8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/bq8;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/bq8;->L$2:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jt5;

    iget-object v1, v0, Llyiahf/vczjk/bq8;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v0, v0, Llyiahf/vczjk/bq8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dq8;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p2, p1

    move-object p1, v1

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/bq8;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/bq8;->L$1:Ljava/lang/Object;

    iget-object p2, p0, Llyiahf/vczjk/dq8;->OooO0OO:Llyiahf/vczjk/mt5;

    iput-object p2, v0, Llyiahf/vczjk/bq8;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/bq8;->label:I

    invoke-virtual {p2, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    const/4 v1, 0x0

    :try_start_0
    iget-object v2, v0, Llyiahf/vczjk/dq8;->OooO0Oo:Llyiahf/vczjk/v74;

    if-ne p1, v2, :cond_4

    iput-object v1, v0, Llyiahf/vczjk/dq8;->OooO0Oo:Llyiahf/vczjk/v74;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_4
    :goto_2
    invoke-interface {p2, v1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_3
    invoke-interface {p2, v1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method

.method public final OooO0O0(ILlyiahf/vczjk/v74;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p3, Llyiahf/vczjk/cq8;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/cq8;

    iget v1, v0, Llyiahf/vczjk/cq8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/cq8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/cq8;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/cq8;-><init>(Llyiahf/vczjk/dq8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/cq8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/cq8;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget p1, v0, Llyiahf/vczjk/cq8;->I$0:I

    iget-object p2, v0, Llyiahf/vczjk/cq8;->L$2:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/jt5;

    iget-object v1, v0, Llyiahf/vczjk/cq8;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v0, v0, Llyiahf/vczjk/cq8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dq8;

    :try_start_0
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_4

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget p1, v0, Llyiahf/vczjk/cq8;->I$0:I

    iget-object p2, v0, Llyiahf/vczjk/cq8;->L$2:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/cq8;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v74;

    iget-object v6, v0, Llyiahf/vczjk/cq8;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/dq8;

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/cq8;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/cq8;->L$1:Ljava/lang/Object;

    iget-object p3, p0, Llyiahf/vczjk/dq8;->OooO0OO:Llyiahf/vczjk/mt5;

    iput-object p3, v0, Llyiahf/vczjk/cq8;->L$2:Ljava/lang/Object;

    iput p1, v0, Llyiahf/vczjk/cq8;->I$0:I

    iput v4, v0, Llyiahf/vczjk/cq8;->label:I

    invoke-virtual {p3, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_4

    goto :goto_3

    :cond_4
    move-object v6, p0

    move-object v2, p2

    move-object p2, p3

    :goto_1
    :try_start_1
    iget-object p3, v6, Llyiahf/vczjk/dq8;->OooO0Oo:Llyiahf/vczjk/v74;

    if-eqz p3, :cond_6

    invoke-interface {p3}, Llyiahf/vczjk/v74;->OooO0Oo()Z

    move-result v7

    if-eqz v7, :cond_6

    iget v7, v6, Llyiahf/vczjk/dq8;->OooO0o0:I

    if-lt v7, p1, :cond_6

    if-ne v7, p1, :cond_5

    iget-boolean v7, v6, Llyiahf/vczjk/dq8;->OooO0O0:Z

    if-eqz v7, :cond_5

    goto :goto_2

    :cond_5
    const/4 v4, 0x0

    goto :goto_5

    :cond_6
    :goto_2
    if-eqz p3, :cond_7

    new-instance v7, Llyiahf/vczjk/aq8;

    iget-object v8, v6, Llyiahf/vczjk/dq8;->OooO00o:Llyiahf/vczjk/gq8;

    invoke-direct {v7, v8}, Llyiahf/vczjk/aq8;-><init>(Llyiahf/vczjk/gq8;)V

    invoke-interface {p3, v7}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_7
    if-eqz p3, :cond_9

    iput-object v6, v0, Llyiahf/vczjk/cq8;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/cq8;->L$1:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/cq8;->L$2:Ljava/lang/Object;

    iput p1, v0, Llyiahf/vczjk/cq8;->I$0:I

    iput v3, v0, Llyiahf/vczjk/cq8;->label:I

    invoke-interface {p3, v0}, Llyiahf/vczjk/v74;->Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_8

    :goto_3
    return-object v1

    :cond_8
    move-object v1, v2

    move-object v0, v6

    :goto_4
    move-object v6, v0

    move-object v2, v1

    :cond_9
    iput-object v2, v6, Llyiahf/vczjk/dq8;->OooO0Oo:Llyiahf/vczjk/v74;

    iput p1, v6, Llyiahf/vczjk/dq8;->OooO0o0:I

    :goto_5
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-interface {p2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object p1

    :goto_6
    invoke-interface {p2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method
