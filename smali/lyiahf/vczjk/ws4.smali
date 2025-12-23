.class public final Llyiahf/vczjk/ws4;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $spec:Llyiahf/vczjk/p13;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p13;"
        }
    .end annotation
.end field

.field final synthetic $totalDelta:J

.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/bt4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/p13;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iput-object p2, p0, Llyiahf/vczjk/ws4;->$spec:Llyiahf/vczjk/p13;

    iput-wide p3, p0, Llyiahf/vczjk/ws4;->$totalDelta:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/ws4;

    iget-object v1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object v2, p0, Llyiahf/vczjk/ws4;->$spec:Llyiahf/vczjk/p13;

    iget-wide v3, p0, Llyiahf/vczjk/ws4;->$totalDelta:J

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ws4;-><init>(Llyiahf/vczjk/bt4;Llyiahf/vczjk/p13;JLlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ws4;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ws4;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ws4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ws4;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    move-object v7, p0

    goto/16 :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/ws4;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/p13;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_2
    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/ws4;->$spec:Llyiahf/vczjk/p13;

    instance-of v1, p1, Llyiahf/vczjk/wz8;

    if-eqz v1, :cond_3

    check-cast p1, Llyiahf/vczjk/wz8;

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/ct4;->OooO00o:Llyiahf/vczjk/wz8;

    :goto_0
    move-object v1, p1

    goto :goto_1

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/ws4;->$spec:Llyiahf/vczjk/p13;

    goto :goto_0

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    iget-wide v4, p0, Llyiahf/vczjk/ws4;->$totalDelta:J

    new-instance v6, Llyiahf/vczjk/u14;

    invoke-direct {v6, v4, v5}, Llyiahf/vczjk/u14;-><init>(J)V

    iput-object v1, p0, Llyiahf/vczjk/ws4;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/ws4;->label:I

    invoke-virtual {p1, v6, p0}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    move-object v7, p0

    goto :goto_3

    :cond_5
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooO0OO:Llyiahf/vczjk/et4;

    invoke-virtual {p1}, Llyiahf/vczjk/et4;->OooO00o()Ljava/lang/Object;

    :cond_6
    move-object v5, v1

    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iget-object p1, p1, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    invoke-virtual {p1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u14;

    iget-wide v3, p1, Llyiahf/vczjk/u14;->OooO00o:J

    iget-wide v6, p0, Llyiahf/vczjk/ws4;->$totalDelta:J

    invoke-static {v3, v4, v6, v7}, Llyiahf/vczjk/u14;->OooO0OO(JJ)J

    move-result-wide v3

    iget-object p1, p0, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    move-wide v6, v3

    iget-object v3, p1, Llyiahf/vczjk/bt4;->OooOOOO:Llyiahf/vczjk/gi;

    new-instance v4, Llyiahf/vczjk/u14;

    invoke-direct {v4, v6, v7}, Llyiahf/vczjk/u14;-><init>(J)V

    move-wide v7, v6

    new-instance v6, Llyiahf/vczjk/vs4;

    invoke-direct {v6, p1, v7, v8}, Llyiahf/vczjk/vs4;-><init>(Llyiahf/vczjk/bt4;J)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ws4;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/ws4;->label:I
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0

    const/4 v8, 0x4

    move-object v7, p0

    :try_start_3
    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    :goto_3
    return-object v0

    :cond_7
    :goto_4
    iget-object p1, v7, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    sget v0, Llyiahf/vczjk/bt4;->OooOo00:I

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bt4;->OooO0o(Z)V

    iget-object p1, v7, Llyiahf/vczjk/ws4;->this$0:Llyiahf/vczjk/bt4;

    iput-boolean v0, p1, Llyiahf/vczjk/bt4;->OooO0oO:Z
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_1

    goto :goto_5

    :catch_0
    move-object v7, p0

    :catch_1
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
