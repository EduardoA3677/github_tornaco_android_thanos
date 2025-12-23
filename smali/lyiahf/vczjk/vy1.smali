.class public final Llyiahf/vczjk/vy1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vy1;->this$0:Llyiahf/vczjk/jz1;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vy1;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vy1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/vy1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/vy1;

    iget-object v1, p0, Llyiahf/vczjk/vy1;->this$0:Llyiahf/vczjk/jz1;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/vy1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vy1;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/vy1;->L$0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Throwable;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/vy1;->this$0:Llyiahf/vczjk/jz1;

    iput v3, p0, Llyiahf/vczjk/vy1;->label:I

    invoke-static {p1, v3, p0}, Llyiahf/vczjk/jz1;->OooO0o(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_2

    :cond_3
    :goto_0
    check-cast p1, Llyiahf/vczjk/n29;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_4

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/vy1;->this$0:Llyiahf/vczjk/jz1;

    invoke-virtual {v1}, Llyiahf/vczjk/jz1;->OooO0oO()Llyiahf/vczjk/yp8;

    move-result-object v1

    iput-object p1, p0, Llyiahf/vczjk/vy1;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/vy1;->label:I

    invoke-virtual {v1}, Llyiahf/vczjk/yp8;->OooO00o()Ljava/lang/Integer;

    move-result-object v1

    if-ne v1, v0, :cond_4

    :goto_2
    return-object v0

    :cond_4
    move-object v0, p1

    move-object p1, v1

    :goto_3
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    new-instance v1, Llyiahf/vczjk/ug7;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/ug7;-><init>(ILjava/lang/Throwable;)V

    move-object p1, v1

    :goto_4
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
