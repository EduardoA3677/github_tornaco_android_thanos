.class public final Llyiahf/vczjk/bi0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $boundsProvider:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $childCoordinates:Llyiahf/vczjk/xn4;

.field final synthetic $parentRect:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/di0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bi0;->this$0:Llyiahf/vczjk/di0;

    iput-object p2, p0, Llyiahf/vczjk/bi0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iput-object p3, p0, Llyiahf/vczjk/bi0;->$boundsProvider:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/bi0;->$parentRect:Llyiahf/vczjk/le3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/bi0;

    iget-object v1, p0, Llyiahf/vczjk/bi0;->this$0:Llyiahf/vczjk/di0;

    iget-object v2, p0, Llyiahf/vczjk/bi0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v3, p0, Llyiahf/vczjk/bi0;->$boundsProvider:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/bi0;->$parentRect:Llyiahf/vczjk/le3;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bi0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/bi0;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bi0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bi0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bi0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/bi0;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/bi0;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/zh0;

    iget-object v1, p0, Llyiahf/vczjk/bi0;->this$0:Llyiahf/vczjk/di0;

    iget-object v2, p0, Llyiahf/vczjk/bi0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v3, p0, Llyiahf/vczjk/bi0;->$boundsProvider:Llyiahf/vczjk/le3;

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/zh0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v4, v4, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/ai0;

    iget-object v2, p0, Llyiahf/vczjk/bi0;->this$0:Llyiahf/vczjk/di0;

    iget-object v3, p0, Llyiahf/vczjk/bi0;->$parentRect:Llyiahf/vczjk/le3;

    invoke-direct {v0, v2, v3, v4}, Llyiahf/vczjk/ai0;-><init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v4, v4, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
