.class public final Llyiahf/vczjk/ib9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $timeMillis:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/kb9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kb9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/kb9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/ib9;->$timeMillis:J

    iput-object p3, p0, Llyiahf/vczjk/ib9;->this$0:Llyiahf/vczjk/kb9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/ib9;

    iget-wide v0, p0, Llyiahf/vczjk/ib9;->$timeMillis:J

    iget-object v2, p0, Llyiahf/vczjk/ib9;->this$0:Llyiahf/vczjk/kb9;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/ib9;-><init>(JLlyiahf/vczjk/kb9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ib9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ib9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ib9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ib9;->label:I

    const-wide/16 v2, 0x8

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v5, :cond_1

    if-ne v1, v4, :cond_0

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

    iget-wide v6, p0, Llyiahf/vczjk/ib9;->$timeMillis:J

    sub-long/2addr v6, v2

    iput v5, p0, Llyiahf/vczjk/ib9;->label:I

    invoke-static {v6, v7, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    iput v4, p0, Llyiahf/vczjk/ib9;->label:I

    invoke-static {v2, v3, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/ib9;->this$0:Llyiahf/vczjk/kb9;

    iget-object p1, p1, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/gy6;

    iget-wide v1, p0, Llyiahf/vczjk/ib9;->$timeMillis:J

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gy6;-><init>(J)V

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
