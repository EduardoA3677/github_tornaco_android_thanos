.class public final Llyiahf/vczjk/ja8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $velocity:J

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ra8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ra8;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ja8;->this$0:Llyiahf/vczjk/ra8;

    iput-wide p2, p0, Llyiahf/vczjk/ja8;->$velocity:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/ja8;

    iget-object v0, p0, Llyiahf/vczjk/ja8;->this$0:Llyiahf/vczjk/ra8;

    iget-wide v1, p0, Llyiahf/vczjk/ja8;->$velocity:J

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/ja8;-><init>(Llyiahf/vczjk/ra8;JLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ja8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ja8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ja8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ja8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ja8;->this$0:Llyiahf/vczjk/ra8;

    iget-object p1, p1, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iget-wide v3, p0, Llyiahf/vczjk/ja8;->$velocity:J

    iput v2, p0, Llyiahf/vczjk/ja8;->label:I

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v2, p1, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v5, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    const/4 v6, 0x0

    if-ne v2, v5, :cond_2

    const/4 v2, 0x1

    :goto_0
    invoke-static {v3, v4, v6, v6, v2}, Llyiahf/vczjk/fea;->OooO00o(JFFI)J

    move-result-wide v2

    goto :goto_1

    :cond_2
    const/4 v2, 0x2

    goto :goto_0

    :goto_1
    new-instance v4, Llyiahf/vczjk/ab8;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/ab8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/yo1;)V

    iget-object v5, p1, Llyiahf/vczjk/db8;->OooO0O0:Llyiahf/vczjk/qg6;

    if-eqz v5, :cond_4

    iget-object v6, p1, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v6}, Llyiahf/vczjk/sa8;->OooO0Oo()Z

    move-result v6

    if-nez v6, :cond_3

    iget-object p1, p1, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {p1}, Llyiahf/vczjk/sa8;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_4

    :cond_3
    check-cast v5, Llyiahf/vczjk/cd;

    invoke-virtual {v5, v2, v3, v4, p0}, Llyiahf/vczjk/cd;->OooO0O0(JLlyiahf/vczjk/ab8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v2, :cond_5

    :goto_2
    move-object v1, p1

    goto :goto_3

    :cond_4
    new-instance p1, Llyiahf/vczjk/ab8;

    iget-object v4, v4, Llyiahf/vczjk/ab8;->this$0:Llyiahf/vczjk/db8;

    invoke-direct {p1, v4, p0}, Llyiahf/vczjk/ab8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/yo1;)V

    iput-wide v2, p1, Llyiahf/vczjk/ab8;->J$0:J

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ab8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v2, :cond_5

    goto :goto_2

    :cond_5
    :goto_3
    if-ne v1, v0, :cond_6

    return-object v0

    :cond_6
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
