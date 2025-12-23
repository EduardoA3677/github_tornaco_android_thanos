.class public final Llyiahf/vczjk/ds6;
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

.field final synthetic $minState:Llyiahf/vczjk/jy4;

.field final synthetic $this_whenStateAtLeast:Llyiahf/vczjk/ky4;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ds6;->$this_whenStateAtLeast:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/ds6;->$minState:Llyiahf/vczjk/jy4;

    iput-object p3, p0, Llyiahf/vczjk/ds6;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/ds6;

    iget-object v1, p0, Llyiahf/vczjk/ds6;->$this_whenStateAtLeast:Llyiahf/vczjk/ky4;

    iget-object v2, p0, Llyiahf/vczjk/ds6;->$minState:Llyiahf/vczjk/jy4;

    iget-object v3, p0, Llyiahf/vczjk/ds6;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/ds6;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ds6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ds6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ds6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ds6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ds6;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ds6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ly4;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ds6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p1, v1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/v74;

    if-eqz p1, :cond_3

    new-instance v1, Llyiahf/vczjk/cs6;

    invoke-direct {v1}, Llyiahf/vczjk/cs6;-><init>()V

    new-instance v3, Llyiahf/vczjk/ly4;

    iget-object v4, p0, Llyiahf/vczjk/ds6;->$this_whenStateAtLeast:Llyiahf/vczjk/ky4;

    iget-object v5, p0, Llyiahf/vczjk/ds6;->$minState:Llyiahf/vczjk/jy4;

    iget-object v6, v1, Llyiahf/vczjk/cs6;->OooOOOO:Llyiahf/vczjk/ec2;

    invoke-direct {v3, v4, v5, v6, p1}, Llyiahf/vczjk/ly4;-><init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ec2;Llyiahf/vczjk/v74;)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/ds6;->$block:Llyiahf/vczjk/ze3;

    iput-object v3, p0, Llyiahf/vczjk/ds6;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/ds6;->label:I

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    move-object v0, v3

    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/ly4;->OooO00o()V

    return-object p1

    :catchall_1
    move-exception p1

    move-object v0, v3

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/ly4;->OooO00o()V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "when[State] methods should have a parent job"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
