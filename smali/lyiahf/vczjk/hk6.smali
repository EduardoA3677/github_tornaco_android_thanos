.class public final Llyiahf/vczjk/hk6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $itemSpacing:F

.field final synthetic $state:Llyiahf/vczjk/km6;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/km6;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hk6;->$density:Llyiahf/vczjk/f62;

    iput-object p2, p0, Llyiahf/vczjk/hk6;->$state:Llyiahf/vczjk/km6;

    iput p3, p0, Llyiahf/vczjk/hk6;->$itemSpacing:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/hk6;

    iget-object v0, p0, Llyiahf/vczjk/hk6;->$density:Llyiahf/vczjk/f62;

    iget-object v1, p0, Llyiahf/vczjk/hk6;->$state:Llyiahf/vczjk/km6;

    iget v2, p0, Llyiahf/vczjk/hk6;->$itemSpacing:F

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/hk6;-><init>(Llyiahf/vczjk/f62;Llyiahf/vczjk/km6;FLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/hk6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hk6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/hk6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/hk6;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hk6;->$density:Llyiahf/vczjk/f62;

    iget-object v0, p0, Llyiahf/vczjk/hk6;->$state:Llyiahf/vczjk/km6;

    iget v1, p0, Llyiahf/vczjk/hk6;->$itemSpacing:F

    invoke-interface {p1, v1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    iget-object v0, v0, Llyiahf/vczjk/km6;->OooO0OO:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
