.class public final Llyiahf/vczjk/zh0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $boundsProvider:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $childCoordinates:Llyiahf/vczjk/xn4;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/di0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zh0;->this$0:Llyiahf/vczjk/di0;

    iput-object p2, p0, Llyiahf/vczjk/zh0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iput-object p3, p0, Llyiahf/vczjk/zh0;->$boundsProvider:Llyiahf/vczjk/le3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/zh0;

    iget-object v0, p0, Llyiahf/vczjk/zh0;->this$0:Llyiahf/vczjk/di0;

    iget-object v1, p0, Llyiahf/vczjk/zh0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v2, p0, Llyiahf/vczjk/zh0;->$boundsProvider:Llyiahf/vczjk/le3;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/zh0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zh0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zh0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zh0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/zh0;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zh0;->this$0:Llyiahf/vczjk/di0;

    iget-object v1, p1, Llyiahf/vczjk/di0;->OooOoOO:Llyiahf/vczjk/um1;

    new-instance v4, Llyiahf/vczjk/yh0;

    iget-object v5, p0, Llyiahf/vczjk/zh0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v6, p0, Llyiahf/vczjk/zh0;->$boundsProvider:Llyiahf/vczjk/le3;

    invoke-direct {v4, p1, v5, v6}, Llyiahf/vczjk/yh0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;)V

    iput v3, p0, Llyiahf/vczjk/zh0;->label:I

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v4}, Llyiahf/vczjk/yh0;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wj7;

    if-eqz p1, :cond_8

    iget-wide v5, v1, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-virtual {v1, p1, v5, v6}, Llyiahf/vczjk/um1;->o00000o0(Llyiahf/vczjk/wj7;J)Z

    move-result p1

    if-nez p1, :cond_8

    new-instance p1, Llyiahf/vczjk/yp0;

    invoke-static {p0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v5

    invoke-direct {p1, v3, v5}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance v5, Llyiahf/vczjk/pm1;

    invoke-direct {v5, v4, p1}, Llyiahf/vczjk/pm1;-><init>(Llyiahf/vczjk/yh0;Llyiahf/vczjk/yp0;)V

    iget-object v6, v1, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v4}, Llyiahf/vczjk/yh0;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/wj7;

    if-nez v4, :cond_2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    goto :goto_4

    :cond_2
    new-instance v7, Llyiahf/vczjk/rh0;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/rh0;-><init>(Llyiahf/vczjk/sh0;Llyiahf/vczjk/pm1;)V

    invoke-virtual {p1, v7}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    iget-object v6, v6, Llyiahf/vczjk/sh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget v7, v6, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v8, 0x0

    invoke-static {v8, v7}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object v7

    iget v9, v7, Llyiahf/vczjk/v14;->OooOOO0:I

    iget v7, v7, Llyiahf/vczjk/v14;->OooOOO:I

    if-gt v9, v7, :cond_6

    :goto_0
    iget-object v10, v6, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v10, v10, v7

    check-cast v10, Llyiahf/vczjk/pm1;

    iget-object v10, v10, Llyiahf/vczjk/pm1;->OooO00o:Llyiahf/vczjk/yh0;

    invoke-virtual {v10}, Llyiahf/vczjk/yh0;->OooO00o()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/wj7;

    if-nez v10, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v4, v10}, Llyiahf/vczjk/wj7;->OooO0o0(Llyiahf/vczjk/wj7;)Llyiahf/vczjk/wj7;

    move-result-object v11

    invoke-virtual {v11, v4}, Llyiahf/vczjk/wj7;->equals(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_4

    add-int/2addr v7, v3

    invoke-virtual {v6, v7, v5}, Llyiahf/vczjk/ws5;->OooO00o(ILjava/lang/Object;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v11, v10}, Llyiahf/vczjk/wj7;->equals(Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_5

    new-instance v10, Ljava/util/concurrent/CancellationException;

    const-string v11, "bringIntoView call interrupted by a newer, non-overlapping call"

    invoke-direct {v10, v11}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    iget v11, v6, Llyiahf/vczjk/ws5;->OooOOOO:I

    sub-int/2addr v11, v3

    if-gt v11, v7, :cond_5

    :goto_1
    iget-object v12, v6, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v12, v12, v7

    check-cast v12, Llyiahf/vczjk/pm1;

    iget-object v12, v12, Llyiahf/vczjk/pm1;->OooO0O0:Llyiahf/vczjk/yp0;

    invoke-virtual {v12, v10}, Llyiahf/vczjk/yp0;->OooOO0o(Ljava/lang/Throwable;)Z

    if-eq v11, v7, :cond_5

    add-int/lit8 v11, v11, 0x1

    goto :goto_1

    :cond_5
    :goto_2
    if-eq v7, v9, :cond_6

    add-int/lit8 v7, v7, -0x1

    goto :goto_0

    :cond_6
    invoke-virtual {v6, v8, v5}, Llyiahf/vczjk/ws5;->OooO00o(ILjava/lang/Object;)V

    :goto_3
    iget-boolean v3, v1, Llyiahf/vczjk/um1;->Oooo0O0:Z

    if-nez v3, :cond_7

    invoke-virtual {v1}, Llyiahf/vczjk/um1;->o0000Ooo()V

    :cond_7
    :goto_4
    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v1, :cond_8

    goto :goto_5

    :cond_8
    move-object p1, v2

    :goto_5
    if-ne p1, v0, :cond_9

    return-object v0

    :cond_9
    return-object v2
.end method
