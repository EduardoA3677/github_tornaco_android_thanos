.class public final Llyiahf/vczjk/pd;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $inputMethodManager:Llyiahf/vczjk/l04;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/td;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/td;Llyiahf/vczjk/l04;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pd;->this$0:Llyiahf/vczjk/td;

    iput-object p2, p0, Llyiahf/vczjk/pd;->$inputMethodManager:Llyiahf/vczjk/l04;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/pd;

    iget-object v0, p0, Llyiahf/vczjk/pd;->this$0:Llyiahf/vczjk/td;

    iget-object v1, p0, Llyiahf/vczjk/pd;->$inputMethodManager:Llyiahf/vczjk/l04;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/pd;-><init>(Llyiahf/vczjk/td;Llyiahf/vczjk/l04;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/pd;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pd;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pd;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/pd;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

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

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/o6;->OooOOo:Llyiahf/vczjk/o6;

    iput v3, p0, Llyiahf/vczjk/pd;->label:I

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/yn5;

    invoke-direct {v3, p1}, Llyiahf/vczjk/yn5;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {v1, p0, v3}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/pd;->this$0:Llyiahf/vczjk/td;

    invoke-virtual {p1}, Llyiahf/vczjk/td;->OooOO0()Llyiahf/vczjk/os5;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance v1, Llyiahf/vczjk/od;

    iget-object v3, p0, Llyiahf/vczjk/pd;->$inputMethodManager:Llyiahf/vczjk/l04;

    const/4 v4, 0x0

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/pd;->label:I

    check-cast p1, Llyiahf/vczjk/jl8;

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/jl8;->OooOOOo(Llyiahf/vczjk/jl8;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    return-object v0

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
