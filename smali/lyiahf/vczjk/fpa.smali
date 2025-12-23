.class public final Llyiahf/vczjk/fpa;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $durationScaleStateFlow:Llyiahf/vczjk/q29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/q29;"
        }
    .end annotation
.end field

.field final synthetic $it:Llyiahf/vczjk/go5;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q29;Llyiahf/vczjk/go5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fpa;->$durationScaleStateFlow:Llyiahf/vczjk/q29;

    iput-object p2, p0, Llyiahf/vczjk/fpa;->$it:Llyiahf/vczjk/go5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/fpa;

    iget-object v0, p0, Llyiahf/vczjk/fpa;->$durationScaleStateFlow:Llyiahf/vczjk/q29;

    iget-object v1, p0, Llyiahf/vczjk/fpa;->$it:Llyiahf/vczjk/go5;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/fpa;-><init>(Llyiahf/vczjk/q29;Llyiahf/vczjk/go5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fpa;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fpa;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fpa;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/fpa;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fpa;->$durationScaleStateFlow:Llyiahf/vczjk/q29;

    new-instance v1, Llyiahf/vczjk/od;

    iget-object v3, p0, Llyiahf/vczjk/fpa;->$it:Llyiahf/vczjk/go5;

    const/16 v4, 0x12

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/fpa;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method
