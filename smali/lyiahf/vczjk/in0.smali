.class public final Llyiahf/vczjk/in0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jn0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jn0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/in0;->this$0:Llyiahf/vczjk/jn0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/in0;

    iget-object v1, p0, Llyiahf/vczjk/in0;->this$0:Llyiahf/vczjk/jn0;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/in0;-><init>(Llyiahf/vczjk/jn0;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/in0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/in0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/in0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/in0;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/in0;->L$1:Ljava/lang/Object;

    check-cast v1, Ljava/util/Iterator;

    iget-object v3, p0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/h43;

    iget-object p1, p0, Llyiahf/vczjk/in0;->this$0:Llyiahf/vczjk/jn0;

    iget-object p1, p1, Llyiahf/vczjk/jn0;->OooO00o:Llyiahf/vczjk/h23;

    iput-object v1, p0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/in0;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/h23;->OooO00o(Llyiahf/vczjk/zo1;)Ljava/io/Serializable;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_2

    :cond_3
    :goto_0
    check-cast p1, Ljava/util/List;

    iget-object v3, p0, Llyiahf/vczjk/in0;->this$0:Llyiahf/vczjk/jn0;

    iget-object v3, v3, Llyiahf/vczjk/jn0;->OooO0Oo:Llyiahf/vczjk/r09;

    invoke-virtual {v3}, Llyiahf/vczjk/k84;->start()Z

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    move-object v3, v1

    move-object v1, p1

    :cond_4
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kx3;

    iput-object v3, p0, Llyiahf/vczjk/in0;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/in0;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/in0;->label:I

    invoke-interface {v3, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_2
    return-object v0

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
