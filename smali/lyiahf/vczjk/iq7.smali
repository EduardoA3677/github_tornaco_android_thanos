.class public final Llyiahf/vczjk/iq7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $mutex:Llyiahf/vczjk/jt5;

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jt5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/iq7;->$mutex:Llyiahf/vczjk/jt5;

    iput-object p2, p0, Llyiahf/vczjk/iq7;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/iq7;

    iget-object v0, p0, Llyiahf/vczjk/iq7;->$mutex:Llyiahf/vczjk/jt5;

    iget-object v1, p0, Llyiahf/vczjk/iq7;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/iq7;-><init>(Llyiahf/vczjk/jt5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/iq7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/iq7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/iq7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/iq7;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/iq7;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/iq7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ze3;

    iget-object v3, p0, Llyiahf/vczjk/iq7;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jt5;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v3

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/iq7;->$mutex:Llyiahf/vczjk/jt5;

    iget-object v1, p0, Llyiahf/vczjk/iq7;->$block:Llyiahf/vczjk/ze3;

    iput-object p1, p0, Llyiahf/vczjk/iq7;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/iq7;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/iq7;->label:I

    invoke-interface {p1, p0}, Llyiahf/vczjk/jt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    :try_start_1
    new-instance v3, Llyiahf/vczjk/hq7;

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/hq7;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/iq7;->L$0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/iq7;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/iq7;->label:I

    invoke-static {v3, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne v1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    move-object v0, p1

    :goto_2
    invoke-interface {v0, v4}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_1
    move-exception v0

    move-object v5, v0

    move-object v0, p1

    move-object p1, v5

    :goto_3
    invoke-interface {v0, v4}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1
.end method
