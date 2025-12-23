.class public final Llyiahf/vczjk/ama;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $currItem$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $items:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $listState:Llyiahf/vczjk/dw4;

.field final synthetic $needScrollTop:I

.field final synthetic $onItemChanged:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ama;->$scope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/ama;->$listState:Llyiahf/vczjk/dw4;

    iput p3, p0, Llyiahf/vczjk/ama;->$needScrollTop:I

    iput-object p4, p0, Llyiahf/vczjk/ama;->$items:Ljava/util/List;

    iput-object p5, p0, Llyiahf/vczjk/ama;->$onItemChanged:Llyiahf/vczjk/oe3;

    iput-object p6, p0, Llyiahf/vczjk/ama;->$currItem$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p7}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 8

    new-instance v0, Llyiahf/vczjk/ama;

    iget-object v1, p0, Llyiahf/vczjk/ama;->$scope:Llyiahf/vczjk/xr1;

    iget-object v2, p0, Llyiahf/vczjk/ama;->$listState:Llyiahf/vczjk/dw4;

    iget v3, p0, Llyiahf/vczjk/ama;->$needScrollTop:I

    iget-object v4, p0, Llyiahf/vczjk/ama;->$items:Ljava/util/List;

    iget-object v5, p0, Llyiahf/vczjk/ama;->$onItemChanged:Llyiahf/vczjk/oe3;

    iget-object v6, p0, Llyiahf/vczjk/ama;->$currItem$delegate:Llyiahf/vczjk/qs5;

    move-object v7, p2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/ama;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ama;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ama;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ama;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ama;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ama;->$scope:Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/zla;

    iget-object v1, p0, Llyiahf/vczjk/ama;->$listState:Llyiahf/vczjk/dw4;

    iget v2, p0, Llyiahf/vczjk/ama;->$needScrollTop:I

    iget-object v3, p0, Llyiahf/vczjk/ama;->$items:Ljava/util/List;

    iget-object v4, p0, Llyiahf/vczjk/ama;->$onItemChanged:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/ama;->$currItem$delegate:Llyiahf/vczjk/qs5;

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/zla;-><init>(Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    const/4 v2, 0x0

    invoke-static {p1, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
