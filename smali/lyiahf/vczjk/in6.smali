.class public final Llyiahf/vczjk/in6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $pagingData:Llyiahf/vczjk/xm6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xm6;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/kn6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kn6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kn6;Llyiahf/vczjk/xm6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/in6;->this$0:Llyiahf/vczjk/kn6;

    iput-object p2, p0, Llyiahf/vczjk/in6;->$pagingData:Llyiahf/vczjk/xm6;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/in6;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/in6;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/in6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/in6;

    iget-object v1, p0, Llyiahf/vczjk/in6;->this$0:Llyiahf/vczjk/kn6;

    iget-object v2, p0, Llyiahf/vczjk/in6;->$pagingData:Llyiahf/vczjk/xm6;

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/in6;-><init>(Llyiahf/vczjk/kn6;Llyiahf/vczjk/xm6;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/in6;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/in6;->this$0:Llyiahf/vczjk/kn6;

    iget-object v1, p0, Llyiahf/vczjk/in6;->$pagingData:Llyiahf/vczjk/xm6;

    iget-object v1, v1, Llyiahf/vczjk/xm6;->OooO0O0:Llyiahf/vczjk/a27;

    iget-object v4, p1, Llyiahf/vczjk/kn6;->OooO0OO:Llyiahf/vczjk/m7a;

    iput-object v1, p1, Llyiahf/vczjk/kn6;->OooO0OO:Llyiahf/vczjk/m7a;

    instance-of p1, v4, Llyiahf/vczjk/gn6;

    if-eqz p1, :cond_2

    check-cast v4, Llyiahf/vczjk/gn6;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-boolean p1, v4, Llyiahf/vczjk/gn6;->OooOOO0:Z

    if-eqz p1, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/a27;->OooO00o()V

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/in6;->$pagingData:Llyiahf/vczjk/xm6;

    iget-object v1, p1, Llyiahf/vczjk/xm6;->OooO00o:Llyiahf/vczjk/f43;

    new-instance v4, Llyiahf/vczjk/tx3;

    iget-object v5, p0, Llyiahf/vczjk/in6;->this$0:Llyiahf/vczjk/kn6;

    const/4 v6, 0x3

    invoke-direct {v4, v6, v5, p1}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput v3, p0, Llyiahf/vczjk/in6;->label:I

    invoke-interface {v1, v4, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_0
    return-object v2
.end method
