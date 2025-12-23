.class public final Llyiahf/vczjk/kh2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kh2;->$drawerState:Llyiahf/vczjk/li2;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/kh2;

    iget-object v0, p0, Llyiahf/vczjk/kh2;->$drawerState:Llyiahf/vczjk/li2;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/kh2;-><init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/kh2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kh2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/kh2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/kh2;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/kh2;->$drawerState:Llyiahf/vczjk/li2;

    iput v3, p0, Llyiahf/vczjk/kh2;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/ni2;->OooOOO0:Llyiahf/vczjk/ni2;

    iget-object p1, p1, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v3, p1, Llyiahf/vczjk/d9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast v3, Llyiahf/vczjk/zv8;

    invoke-virtual {v3}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v3

    invoke-static {p1, v1, v3, p0}, Llyiahf/vczjk/t51;->OooOOO0(Llyiahf/vczjk/d9;Ljava/lang/Object;FLlyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    return-object v2
.end method
