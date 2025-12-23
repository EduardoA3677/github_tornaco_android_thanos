.class public final Llyiahf/vczjk/rr9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/sr9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sr9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rr9;->this$0:Llyiahf/vczjk/sr9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/rr9;

    iget-object v0, p0, Llyiahf/vczjk/rr9;->this$0:Llyiahf/vczjk/sr9;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/rr9;-><init>(Llyiahf/vczjk/sr9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rr9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/rr9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/rr9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/fl7;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/rr9;->this$0:Llyiahf/vczjk/sr9;

    iget-object v3, v1, Llyiahf/vczjk/sr9;->OooOoOO:Llyiahf/vczjk/rr5;

    check-cast v3, Llyiahf/vczjk/sr5;

    iget-object v3, v3, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    new-instance v4, Llyiahf/vczjk/tx3;

    const/16 v5, 0x9

    invoke-direct {v4, v5, p1, v1}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput v2, p0, Llyiahf/vczjk/rr9;->label:I

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/jl8;->OooOOOo(Llyiahf/vczjk/jl8;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method
