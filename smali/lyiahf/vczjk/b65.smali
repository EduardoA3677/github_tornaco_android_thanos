.class public final Llyiahf/vczjk/b65;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;

.field final synthetic $this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iput-object p2, p0, Llyiahf/vczjk/b65;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/b65;

    iget-object v1, p0, Llyiahf/vczjk/b65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iget-object v2, p0, Llyiahf/vczjk/b65;->$observer:Llyiahf/vczjk/bi9;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/b65;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/b65;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/b65;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b65;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/b65;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/b65;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/b65;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    sget-object v0, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v1, Llyiahf/vczjk/z55;

    iget-object v2, p0, Llyiahf/vczjk/b65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iget-object v3, p0, Llyiahf/vczjk/b65;->$observer:Llyiahf/vczjk/bi9;

    const/4 v4, 0x0

    invoke-direct {v1, v2, v3, v4}, Llyiahf/vczjk/z55;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x1

    invoke-static {p1, v4, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v1, Llyiahf/vczjk/a65;

    iget-object v3, p0, Llyiahf/vczjk/b65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iget-object v5, p0, Llyiahf/vczjk/b65;->$observer:Llyiahf/vczjk/bi9;

    invoke-direct {v1, v3, v5, v4}, Llyiahf/vczjk/a65;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v4, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
