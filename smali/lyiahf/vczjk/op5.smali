.class public final Llyiahf/vczjk/op5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/tp5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/op5;

    iget-object v1, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/op5;-><init>(Llyiahf/vczjk/tp5;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/op5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/op5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/op5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/op5;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v4, :cond_2

    if-ne v1, v3, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xr1;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object v10, p0

    :cond_0
    move-object p1, v1

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    move-object v10, p0

    goto/16 :goto_4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xr1;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    :goto_0
    :try_start_2
    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Oooooo0(Llyiahf/vczjk/or1;)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iget-object v1, v1, Llyiahf/vczjk/tp5;->OooO0o0:Llyiahf/vczjk/jj0;

    iput-object p1, p0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/op5;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/jj0;->OooO00o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_4

    move-object v10, p0

    goto :goto_2

    :cond_4
    move-object v11, v1

    move-object v1, p1

    move-object p1, v11

    :goto_1
    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/fp5;

    iget-object p1, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iget-object p1, p1, Llyiahf/vczjk/tp5;->OooO0Oo:Llyiahf/vczjk/f62;

    sget v5, Llyiahf/vczjk/ep5;->OooO00o:F

    invoke-interface {p1, v5}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v8

    iget-object p1, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iget-object p1, p1, Llyiahf/vczjk/tp5;->OooO0Oo:Llyiahf/vczjk/f62;

    sget v5, Llyiahf/vczjk/ep5;->OooO0O0:F

    invoke-interface {p1, v5}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v9

    iget-object v5, p0, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iget-object v6, v5, Llyiahf/vczjk/tp5;->OooO00o:Llyiahf/vczjk/db8;

    iput-object v1, p0, Llyiahf/vczjk/op5;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/op5;->label:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    move-object v10, p0

    :try_start_3
    invoke-static/range {v5 .. v10}, Llyiahf/vczjk/tp5;->OooO0O0(Llyiahf/vczjk/tp5;Llyiahf/vczjk/db8;Llyiahf/vczjk/fp5;FFLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-ne p1, v0, :cond_0

    :goto_2
    return-object v0

    :catchall_1
    move-exception v0

    goto :goto_3

    :catchall_2
    move-exception v0

    move-object v10, p0

    :goto_3
    move-object p1, v0

    goto :goto_4

    :cond_5
    move-object v10, p0

    iget-object p1, v10, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iput-object v2, p1, Llyiahf/vczjk/tp5;->OooO0oO:Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_4
    iget-object v0, v10, Llyiahf/vczjk/op5;->this$0:Llyiahf/vczjk/tp5;

    iput-object v2, v0, Llyiahf/vczjk/tp5;->OooO0oO:Llyiahf/vczjk/r09;

    throw p1
.end method
