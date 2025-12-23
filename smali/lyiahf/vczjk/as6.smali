.class public final Llyiahf/vczjk/as6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xn5;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/cn4;

.field public final OooOOO0:Llyiahf/vczjk/xn5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xn5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/as6;->OooOOO0:Llyiahf/vczjk/xn5;

    new-instance p1, Llyiahf/vczjk/cn4;

    invoke-direct {p1}, Llyiahf/vczjk/cn4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/as6;->OooOOO:Llyiahf/vczjk/cn4;

    return-void
.end method


# virtual methods
.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p1, Llyiahf/vczjk/zr6;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/zr6;

    iget v1, v0, Llyiahf/vczjk/zr6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/zr6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/zr6;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/zr6;-><init>(Llyiahf/vczjk/as6;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/zr6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/zr6;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p2, v0, Llyiahf/vczjk/zr6;->L$1:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/oe3;

    iget-object v2, v0, Llyiahf/vczjk/zr6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/as6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/as6;->OooOOO:Llyiahf/vczjk/cn4;

    iput-object p0, v0, Llyiahf/vczjk/zr6;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/zr6;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/zr6;->label:I

    iget-object v2, p1, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    iget-boolean v5, p1, Llyiahf/vczjk/cn4;->OooO0Oo:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v2

    if-eqz v5, :cond_4

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_1

    :cond_4
    new-instance v2, Llyiahf/vczjk/yp0;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v5

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOoo()V

    iget-object v4, p1, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    monitor-enter v4

    :try_start_1
    iget-object v5, p1, Llyiahf/vczjk/cn4;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v4

    new-instance v4, Llyiahf/vczjk/bn4;

    invoke-direct {v4, p1, v2}, Llyiahf/vczjk/bn4;-><init>(Llyiahf/vczjk/cn4;Llyiahf/vczjk/yp0;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_5

    goto :goto_1

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    if-ne p1, v1, :cond_6

    goto :goto_3

    :cond_6
    move-object v2, p0

    :goto_2
    iget-object p1, v2, Llyiahf/vczjk/as6;->OooOOO0:Llyiahf/vczjk/xn5;

    const/4 v2, 0x0

    iput-object v2, v0, Llyiahf/vczjk/zr6;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/zr6;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/zr6;->label:I

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_7

    :goto_3
    return-object v1

    :cond_7
    return-object p1

    :catchall_0
    move-exception p1

    monitor-exit v4

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v2

    throw p1
.end method
