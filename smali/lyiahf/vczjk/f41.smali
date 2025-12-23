.class public final Llyiahf/vczjk/f41;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $keyCode:J

.field J$0:J

.field J$1:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f41;->this$0:Llyiahf/vczjk/g41;

    iput-wide p2, p0, Llyiahf/vczjk/f41;->$keyCode:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/f41;

    iget-object v0, p0, Llyiahf/vczjk/f41;->this$0:Llyiahf/vczjk/g41;

    iget-wide v1, p0, Llyiahf/vczjk/f41;->$keyCode:J

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/f41;-><init>(Llyiahf/vczjk/g41;JLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f41;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/f41;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/f41;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/f41;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-wide v4, p0, Llyiahf/vczjk/f41;->J$1:J

    iget-wide v6, p0, Llyiahf/vczjk/f41;->J$0:J

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/f41;->this$0:Llyiahf/vczjk/g41;

    sget-object v1, Llyiahf/vczjk/ch1;->OooOOoo:Llyiahf/vczjk/l39;

    invoke-static {p1, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gga;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p1}, Llyiahf/vczjk/gga;->OooO00o()J

    move-result-wide v4

    const-wide/16 v6, 0x28

    iput-wide v6, p0, Llyiahf/vczjk/f41;->J$0:J

    iput-wide v4, p0, Llyiahf/vczjk/f41;->J$1:J

    iput v3, p0, Llyiahf/vczjk/f41;->label:I

    invoke-static {v6, v7, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_2

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/f41;->this$0:Llyiahf/vczjk/g41;

    iget-object p1, p1, Llyiahf/vczjk/g41;->OoooOo0:Llyiahf/vczjk/vr5;

    iget-wide v8, p0, Llyiahf/vczjk/f41;->$keyCode:J

    invoke-virtual {p1, v8, v9}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y31;

    if-nez p1, :cond_4

    goto :goto_1

    :cond_4
    iput-boolean v3, p1, Llyiahf/vczjk/y31;->OooO0O0:Z

    :goto_1
    sub-long/2addr v4, v6

    iput v2, p0, Llyiahf/vczjk/f41;->label:I

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_2
    return-object v0

    :cond_5
    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/f41;->this$0:Llyiahf/vczjk/g41;

    iget-object p1, p1, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
