.class public final Llyiahf/vczjk/fm6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $it:Llyiahf/vczjk/gv4;

.field final synthetic $pageOffset:F

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gv4;Llyiahf/vczjk/km6;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fm6;->$it:Llyiahf/vczjk/gv4;

    iput-object p2, p0, Llyiahf/vczjk/fm6;->this$0:Llyiahf/vczjk/km6;

    iput p3, p0, Llyiahf/vczjk/fm6;->$pageOffset:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/fm6;

    iget-object v1, p0, Llyiahf/vczjk/fm6;->$it:Llyiahf/vczjk/gv4;

    iget-object v2, p0, Llyiahf/vczjk/fm6;->this$0:Llyiahf/vczjk/km6;

    iget v3, p0, Llyiahf/vczjk/fm6;->$pageOffset:F

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/fm6;-><init>(Llyiahf/vczjk/gv4;Llyiahf/vczjk/km6;FLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/fm6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/v98;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fm6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fm6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fm6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/fm6;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fm6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v98;

    iget-object v0, p0, Llyiahf/vczjk/fm6;->$it:Llyiahf/vczjk/gv4;

    check-cast v0, Llyiahf/vczjk/tv4;

    iget v0, v0, Llyiahf/vczjk/tv4;->OooOOo0:I

    iget-object v1, p0, Llyiahf/vczjk/fm6;->this$0:Llyiahf/vczjk/km6;

    iget-object v1, v1, Llyiahf/vczjk/km6;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    add-int/2addr v1, v0

    int-to-float v0, v1

    iget v1, p0, Llyiahf/vczjk/fm6;->$pageOffset:F

    mul-float/2addr v0, v1

    invoke-interface {p1, v0}, Llyiahf/vczjk/v98;->OooO00o(F)F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
