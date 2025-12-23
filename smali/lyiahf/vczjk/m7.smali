.class public final Llyiahf/vczjk/m7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/d9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/d9;"
        }
    .end annotation
.end field

.field final synthetic $velocity:F

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d9;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m7;->$state:Llyiahf/vczjk/d9;

    iput p2, p0, Llyiahf/vczjk/m7;->$velocity:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/m7;

    iget-object v0, p0, Llyiahf/vczjk/m7;->$state:Llyiahf/vczjk/d9;

    iget v1, p0, Llyiahf/vczjk/m7;->$velocity:F

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/m7;-><init>(Llyiahf/vczjk/d9;FLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/m7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/m7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/m7;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/m7;->$state:Llyiahf/vczjk/d9;

    iget v1, p0, Llyiahf/vczjk/m7;->$velocity:F

    iput v3, p0, Llyiahf/vczjk/m7;->label:I

    iget-object v3, p1, Llyiahf/vczjk/d9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {p1}, Llyiahf/vczjk/d9;->OooO0o()F

    move-result v4

    invoke-virtual {p1, v4, v1, v3}, Llyiahf/vczjk/d9;->OooO0OO(FFLjava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    iget-object v5, p1, Llyiahf/vczjk/d9;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-interface {v5, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-static {p1, v4, v1, p0}, Llyiahf/vczjk/t51;->OooOOO0(Llyiahf/vczjk/d9;Ljava/lang/Object;FLlyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    goto :goto_0

    :cond_3
    invoke-static {p1, v3, v1, p0}, Llyiahf/vczjk/t51;->OooOOO0(Llyiahf/vczjk/d9;Ljava/lang/Object;FLlyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    :goto_0
    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    return-object v2
.end method
