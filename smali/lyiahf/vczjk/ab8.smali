.class public final Llyiahf/vczjk/ab8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic J$0:J

.field J$1:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/db8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ab8;

    iget-object v1, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/ab8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/yo1;)V

    check-cast p1, Llyiahf/vczjk/fea;

    iget-wide p1, p1, Llyiahf/vczjk/fea;->OooO00o:J

    iput-wide p1, v0, Llyiahf/vczjk/ab8;->J$0:J

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/fea;

    iget-wide v0, p1, Llyiahf/vczjk/fea;->OooO00o:J

    check-cast p2, Llyiahf/vczjk/yo1;

    new-instance p1, Llyiahf/vczjk/ab8;

    iget-object v2, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/ab8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/yo1;)V

    iput-wide v0, p1, Llyiahf/vczjk/ab8;->J$0:J

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ab8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v6, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ab8;->label:I

    const/4 v1, 0x3

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v0, :cond_3

    if-eq v0, v3, :cond_2

    if-eq v0, v2, :cond_1

    if-ne v0, v1, :cond_0

    iget-wide v0, p0, Llyiahf/vczjk/ab8;->J$1:J

    iget-wide v2, p0, Llyiahf/vczjk/ab8;->J$0:J

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-wide v7, v2

    move-wide v3, v0

    move-object v0, p1

    goto/16 :goto_3

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-wide v2, p0, Llyiahf/vczjk/ab8;->J$1:J

    iget-wide v7, p0, Llyiahf/vczjk/ab8;->J$0:J

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v0, p1

    goto :goto_1

    :cond_2
    iget-wide v3, p0, Llyiahf/vczjk/ab8;->J$0:J

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v0, p1

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-wide v7, p0, Llyiahf/vczjk/ab8;->J$0:J

    iget-object v0, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    iget-object v0, v0, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    iput-wide v7, p0, Llyiahf/vczjk/ab8;->J$0:J

    iput v3, p0, Llyiahf/vczjk/ab8;->label:I

    invoke-virtual {v0, v7, v8, p0}, Llyiahf/vczjk/fz5;->OooO0O0(JLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v6, :cond_4

    goto :goto_2

    :cond_4
    move-wide v3, v7

    :goto_0
    check-cast v0, Llyiahf/vczjk/fea;

    iget-wide v7, v0, Llyiahf/vczjk/fea;->OooO00o:J

    invoke-static {v3, v4, v7, v8}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v7

    iget-object v0, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    iput-wide v3, p0, Llyiahf/vczjk/ab8;->J$0:J

    iput-wide v7, p0, Llyiahf/vczjk/ab8;->J$1:J

    iput v2, p0, Llyiahf/vczjk/ab8;->label:I

    invoke-virtual {v0, v7, v8, p0}, Llyiahf/vczjk/db8;->OooO0O0(JLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v6, :cond_5

    goto :goto_2

    :cond_5
    move-wide v11, v7

    move-wide v7, v3

    move-wide v2, v11

    :goto_1
    check-cast v0, Llyiahf/vczjk/fea;

    iget-wide v9, v0, Llyiahf/vczjk/fea;->OooO00o:J

    iget-object v0, p0, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    iget-object v0, v0, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    invoke-static {v2, v3, v9, v10}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v2

    iput-wide v7, p0, Llyiahf/vczjk/ab8;->J$0:J

    iput-wide v9, p0, Llyiahf/vczjk/ab8;->J$1:J

    iput v1, p0, Llyiahf/vczjk/ab8;->label:I

    move-object v5, p0

    move-wide v1, v2

    move-wide v3, v9

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/fz5;->OooO00o(JJLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v6, :cond_6

    :goto_2
    return-object v6

    :cond_6
    :goto_3
    check-cast v0, Llyiahf/vczjk/fea;

    iget-wide v0, v0, Llyiahf/vczjk/fea;->OooO00o:J

    invoke-static {v3, v4, v0, v1}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v0

    invoke-static {v7, v8, v0, v1}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/fea;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object v2
.end method
