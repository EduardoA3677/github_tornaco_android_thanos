.class public final Llyiahf/vczjk/zj6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $count:I

.field final synthetic $state:Llyiahf/vczjk/km6;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/km6;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zj6;->$state:Llyiahf/vczjk/km6;

    iput p2, p0, Llyiahf/vczjk/zj6;->$count:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/zj6;

    iget-object v0, p0, Llyiahf/vczjk/zj6;->$state:Llyiahf/vczjk/km6;

    iget v1, p0, Llyiahf/vczjk/zj6;->$count:I

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/zj6;-><init>(Llyiahf/vczjk/km6;ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zj6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zj6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zj6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/zj6;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/zj6;->$state:Llyiahf/vczjk/km6;

    iget v0, p0, Llyiahf/vczjk/zj6;->$count:I

    add-int/lit8 v0, v0, -0x1

    invoke-virtual {p1}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v1

    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    move-result v0

    if-gez v0, :cond_0

    const/4 v0, 0x0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v1

    if-eq v0, v1, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/km6;->OooO0O0:Llyiahf/vczjk/qs5;

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
