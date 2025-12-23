.class public final Llyiahf/vczjk/zla;
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

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zla;->$listState:Llyiahf/vczjk/dw4;

    iput p2, p0, Llyiahf/vczjk/zla;->$needScrollTop:I

    iput-object p3, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/zla;->$onItemChanged:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/zla;->$currItem$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/zla;

    iget-object v1, p0, Llyiahf/vczjk/zla;->$listState:Llyiahf/vczjk/dw4;

    iget v2, p0, Llyiahf/vczjk/zla;->$needScrollTop:I

    iget-object v3, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    iget-object v4, p0, Llyiahf/vczjk/zla;->$onItemChanged:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/zla;->$currItem$delegate:Llyiahf/vczjk/qs5;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/zla;-><init>(Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zla;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zla;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zla;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/zla;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zla;->$listState:Llyiahf/vczjk/dw4;

    iget v1, p0, Llyiahf/vczjk/zla;->$needScrollTop:I

    int-to-float v1, v1

    iput v2, p0, Llyiahf/vczjk/zla;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x7

    const/4 v4, 0x0

    invoke-static {v4, v4, v2, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v2

    invoke-static {p1, v1, v2, p0}, Llyiahf/vczjk/os9;->OooOOOO(Llyiahf/vczjk/sa8;FLlyiahf/vczjk/wz8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/zla;->$listState:Llyiahf/vczjk/dw4;

    iget-object v0, v0, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v0}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    rem-int/2addr v0, v1

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/zla;->$currItem$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/zla;->$currItem$delegate:Llyiahf/vczjk/qs5;

    iget-object v0, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    iget-object v1, p0, Llyiahf/vczjk/zla;->$listState:Llyiahf/vczjk/dw4;

    iget-object v1, v1, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v1}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/zla;->$items:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    rem-int/2addr v1, v2

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zla;->$onItemChanged:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/zla;->$currItem$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
