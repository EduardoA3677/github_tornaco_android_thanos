.class public final Llyiahf/vczjk/wp9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/yp9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wp9;->this$0:Llyiahf/vczjk/yp9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/wp9;

    iget-object v0, p0, Llyiahf/vczjk/wp9;->this$0:Llyiahf/vczjk/yp9;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/wp9;-><init>(Llyiahf/vczjk/yp9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/wp9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wp9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wp9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/wp9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wp9;->this$0:Llyiahf/vczjk/yp9;

    iget-object p1, p1, Llyiahf/vczjk/yp9;->OooOOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s55;

    iget-object v1, p1, Llyiahf/vczjk/s55;->OooO0OO:Llyiahf/vczjk/r09;

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/k84;->OooO0Oo()Z

    move-result v1

    if-ne v1, v2, :cond_2

    goto :goto_0

    :cond_2
    new-instance v1, Llyiahf/vczjk/r55;

    const/4 v3, 0x0

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/r55;-><init>(Llyiahf/vczjk/s55;Llyiahf/vczjk/yo1;)V

    iget-object v4, p1, Llyiahf/vczjk/s55;->OooO00o:Llyiahf/vczjk/to1;

    const/4 v5, 0x3

    invoke-static {v4, v3, v3, v1, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v1

    iput-object v1, p1, Llyiahf/vczjk/s55;->OooO0OO:Llyiahf/vczjk/r09;

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/wp9;->this$0:Llyiahf/vczjk/yp9;

    iget-object p1, p1, Llyiahf/vczjk/yp9;->OooOOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s55;

    iget-object p1, p1, Llyiahf/vczjk/s55;->OooO0O0:Llyiahf/vczjk/s29;

    new-instance v1, Llyiahf/vczjk/od;

    iget-object v3, p0, Llyiahf/vczjk/wp9;->this$0:Llyiahf/vczjk/yp9;

    const/16 v4, 0x11

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/wp9;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    return-object v0
.end method
