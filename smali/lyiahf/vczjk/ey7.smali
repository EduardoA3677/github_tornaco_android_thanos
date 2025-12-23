.class public abstract Llyiahf/vczjk/ey7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/mt5;

.field public final OooO0O0:Llyiahf/vczjk/v51;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/mt5;

    invoke-direct {v0}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ey7;->OooO00o:Llyiahf/vczjk/mt5;

    invoke-static {}, Llyiahf/vczjk/l4a;->OooO0O0()Llyiahf/vczjk/v51;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ey7;->OooO0O0:Llyiahf/vczjk/v51;

    return-void
.end method


# virtual methods
.method public abstract OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
.end method

.method public final OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p1, Llyiahf/vczjk/dy7;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/dy7;

    iget v1, v0, Llyiahf/vczjk/dy7;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/dy7;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/dy7;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/dy7;-><init>(Llyiahf/vczjk/ey7;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/dy7;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/dy7;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/dy7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v0, v0, Llyiahf/vczjk/dy7;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ey7;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_5

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/dy7;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v5, v0, Llyiahf/vczjk/dy7;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/ey7;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v2

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ey7;->OooO0O0:Llyiahf/vczjk/v51;

    invoke-virtual {p1}, Llyiahf/vczjk/k84;->Oooo0o0()Z

    move-result p1

    if-eqz p1, :cond_4

    return-object v3

    :cond_4
    iput-object p0, v0, Llyiahf/vczjk/dy7;->L$0:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/ey7;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object p1, v0, Llyiahf/vczjk/dy7;->L$1:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/dy7;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_5

    goto :goto_2

    :cond_5
    move-object v5, p0

    :goto_1
    :try_start_1
    iget-object v2, v5, Llyiahf/vczjk/ey7;->OooO0O0:Llyiahf/vczjk/v51;

    invoke-virtual {v2}, Llyiahf/vczjk/k84;->Oooo0o0()Z

    move-result v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v2, :cond_6

    invoke-interface {p1, v6}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object v3

    :cond_6
    :try_start_2
    iput-object v5, v0, Llyiahf/vczjk/dy7;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/dy7;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/dy7;->label:I

    invoke-virtual {v5, v0}, Llyiahf/vczjk/ey7;->OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    if-ne v0, v1, :cond_7

    :goto_2
    return-object v1

    :cond_7
    move-object v1, p1

    move-object v0, v5

    :goto_3
    :try_start_3
    iget-object p1, v0, Llyiahf/vczjk/ey7;->OooO0O0:Llyiahf/vczjk/v51;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/k84;->Oooo0oo(Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    invoke-interface {v1, v6}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object v3

    :goto_4
    move-object v1, p1

    move-object p1, v0

    goto :goto_5

    :catchall_1
    move-exception v0

    goto :goto_4

    :goto_5
    invoke-interface {v1, v6}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method
