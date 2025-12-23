.class public final Llyiahf/vczjk/k29;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field synthetic I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/m29;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k29;->this$0:Llyiahf/vczjk/m29;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/k29;

    iget-object v1, p0, Llyiahf/vczjk/k29;->this$0:Llyiahf/vczjk/m29;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/k29;-><init>(Llyiahf/vczjk/m29;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    iput p2, v0, Llyiahf/vczjk/k29;->I$0:I

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k29;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/k29;->label:I

    const/4 v2, 0x5

    const/4 v3, 0x4

    const/4 v4, 0x3

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eqz v1, :cond_5

    if-eq v1, v6, :cond_4

    if-eq v1, v5, :cond_3

    if-eq v1, v4, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_4
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_5

    :cond_5
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/h43;

    iget p1, p0, Llyiahf/vczjk/k29;->I$0:I

    if-lez p1, :cond_6

    sget-object p1, Llyiahf/vczjk/pl8;->OooOOO0:Llyiahf/vczjk/pl8;

    iput v6, p0, Llyiahf/vczjk/k29;->label:I

    invoke-interface {v1, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_a

    goto :goto_4

    :cond_6
    iget-object p1, p0, Llyiahf/vczjk/k29;->this$0:Llyiahf/vczjk/m29;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/k29;->label:I

    const-wide/16 v5, 0x0

    invoke-static {v5, v6, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    goto :goto_4

    :cond_7
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/k29;->this$0:Llyiahf/vczjk/m29;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/pl8;->OooOOO:Llyiahf/vczjk/pl8;

    iput-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/k29;->label:I

    invoke-interface {v1, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    goto :goto_4

    :cond_8
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/k29;->this$0:Llyiahf/vczjk/m29;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object v1, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/k29;->label:I

    const-wide v3, 0x7fffffffffffffffL

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_9

    goto :goto_4

    :cond_9
    :goto_3
    sget-object p1, Llyiahf/vczjk/pl8;->OooOOOO:Llyiahf/vczjk/pl8;

    const/4 v3, 0x0

    iput-object v3, p0, Llyiahf/vczjk/k29;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/k29;->label:I

    invoke-interface {v1, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_a

    :goto_4
    return-object v0

    :cond_a
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
