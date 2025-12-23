.class public final Llyiahf/vczjk/jh;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $consumed:Z

.field final synthetic $viewVelocity:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/nh;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/jh;->$consumed:Z

    iput-object p2, p0, Llyiahf/vczjk/jh;->this$0:Llyiahf/vczjk/nh;

    iput-wide p3, p0, Llyiahf/vczjk/jh;->$viewVelocity:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/jh;

    iget-boolean v1, p0, Llyiahf/vczjk/jh;->$consumed:Z

    iget-object v2, p0, Llyiahf/vczjk/jh;->this$0:Llyiahf/vczjk/nh;

    iget-wide v3, p0, Llyiahf/vczjk/jh;->$viewVelocity:J

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/jh;-><init>(ZLlyiahf/vczjk/nh;JLlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/jh;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jh;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/jh;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/jh;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v6, p0

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean p1, p0, Llyiahf/vczjk/jh;->$consumed:Z

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/jh;->this$0:Llyiahf/vczjk/nh;

    iget-object v4, p1, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    iget-wide v7, p0, Llyiahf/vczjk/jh;->$viewVelocity:J

    iput v3, p0, Llyiahf/vczjk/jh;->label:I

    const-wide/16 v5, 0x0

    move-object v9, p0

    invoke-virtual/range {v4 .. v9}, Llyiahf/vczjk/fz5;->OooO00o(JJLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    move-object v6, v9

    if-ne p1, v0, :cond_4

    goto :goto_0

    :cond_3
    move-object v6, p0

    iget-object p1, v6, Llyiahf/vczjk/jh;->this$0:Llyiahf/vczjk/nh;

    iget-object v1, p1, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    move p1, v2

    iget-wide v2, v6, Llyiahf/vczjk/jh;->$viewVelocity:J

    iput p1, v6, Llyiahf/vczjk/jh;->label:I

    const-wide/16 v4, 0x0

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/fz5;->OooO00o(JJLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_0
    return-object v0

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
