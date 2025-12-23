.class public final Llyiahf/vczjk/rm9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $linkStateObserver:Llyiahf/vczjk/i05;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i05;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/rm9;

    iget-object v0, p0, Llyiahf/vczjk/rm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/rm9;-><init>(Llyiahf/vczjk/i05;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rm9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rm9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/rm9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/rm9;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/rm9;->$linkStateObserver:Llyiahf/vczjk/i05;

    iput v3, p0, Llyiahf/vczjk/rm9;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/as5;

    invoke-direct {v1}, Llyiahf/vczjk/as5;-><init>()V

    iget-object v2, p1, Llyiahf/vczjk/i05;->OooO00o:Llyiahf/vczjk/rr5;

    check-cast v2, Llyiahf/vczjk/sr5;

    iget-object v2, v2, Llyiahf/vczjk/sr5;->OooO00o:Llyiahf/vczjk/jl8;

    new-instance v3, Llyiahf/vczjk/tx3;

    const/4 v4, 0x1

    invoke-direct {v3, v4, v1, p1}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2, v3, p0}, Llyiahf/vczjk/jl8;->OooOOOo(Llyiahf/vczjk/jl8;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method
