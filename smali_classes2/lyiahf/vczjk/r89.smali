.class public final Llyiahf/vczjk/r89;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $code:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/v89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v89;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r89;->this$0:Llyiahf/vczjk/v89;

    iput-object p2, p0, Llyiahf/vczjk/r89;->$code:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/r89;

    iget-object v0, p0, Llyiahf/vczjk/r89;->this$0:Llyiahf/vczjk/v89;

    iget-object v1, p0, Llyiahf/vczjk/r89;->$code:Ljava/lang/String;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/r89;-><init>(Llyiahf/vczjk/v89;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/r89;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r89;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/r89;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r89;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/r89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object p1, p1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/g99;

    sget-object v8, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    const/4 v5, 0x0

    const/4 v9, 0x7

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/g99;->OooO00o(Llyiahf/vczjk/g99;ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;I)Llyiahf/vczjk/g99;

    move-result-object p1

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    iput v3, p0, Llyiahf/vczjk/r89;->label:I

    const-wide/16 v3, 0x8ae

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/r89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tq7;

    iget-object v1, p0, Llyiahf/vczjk/r89;->$code:Ljava/lang/String;

    iput v2, p0, Llyiahf/vczjk/r89;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/tq7;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/r89;->this$0:Llyiahf/vczjk/v89;

    check-cast p1, Llyiahf/vczjk/xs7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v1, p1, Llyiahf/vczjk/us7;

    if-eqz v1, :cond_8

    const/4 v2, 0x0

    if-eqz v1, :cond_5

    check-cast p1, Llyiahf/vczjk/us7;

    goto :goto_3

    :cond_5
    move-object p1, v2

    :goto_3
    if-eqz p1, :cond_6

    iget-object v2, p1, Llyiahf/vczjk/us7;->OooO00o:Ljava/lang/Object;

    :cond_6
    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v2, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;->getRemainingMillis()J

    move-result-wide v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x16d

    int-to-long v3, p1

    const-wide/32 v5, 0x5265c00

    mul-long/2addr v3, v5

    cmp-long p1, v1, v3

    if-ltz p1, :cond_7

    div-long/2addr v1, v3

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, " \u5e74\uff08Year\uff09"

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_4

    :cond_7
    div-long/2addr v1, v5

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p1, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, " \u5929\uff08Days\uff09"

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    :goto_4
    iget-object v0, v0, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v0, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/g99;

    new-instance v6, Llyiahf/vczjk/p7a;

    invoke-direct {v6, p1}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

    const/4 v3, 0x0

    const/4 v7, 0x7

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/g99;->OooO00o(Llyiahf/vczjk/g99;ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;I)Llyiahf/vczjk/g99;

    move-result-object p1

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    goto :goto_5

    :cond_8
    instance-of v1, p1, Llyiahf/vczjk/ss7;

    if-eqz v1, :cond_9

    iget-object v0, v0, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v0, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/g99;

    new-instance v6, Llyiahf/vczjk/o7a;

    check-cast p1, Llyiahf/vczjk/ss7;

    iget-object p1, p1, Llyiahf/vczjk/ss7;->OooO00o:Ljava/lang/Throwable;

    invoke-direct {v6, p1}, Llyiahf/vczjk/o7a;-><init>(Ljava/lang/Throwable;)V

    const/4 v3, 0x0

    const/4 v7, 0x7

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/g99;->OooO00o(Llyiahf/vczjk/g99;ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;I)Llyiahf/vczjk/g99;

    move-result-object p1

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    :cond_9
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
