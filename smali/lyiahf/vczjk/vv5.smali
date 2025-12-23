.class public final Llyiahf/vczjk/vv5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $backStackEntry:Llyiahf/vczjk/ku5;

.field final synthetic $transitionState:Llyiahf/vczjk/xc8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xc8;"
        }
    .end annotation
.end field

.field final synthetic $value:F

.field label:I


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/xc8;Llyiahf/vczjk/ku5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/vv5;->$value:F

    iput-object p2, p0, Llyiahf/vczjk/vv5;->$transitionState:Llyiahf/vczjk/xc8;

    iput-object p3, p0, Llyiahf/vczjk/vv5;->$backStackEntry:Llyiahf/vczjk/ku5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/vv5;

    iget v0, p0, Llyiahf/vczjk/vv5;->$value:F

    iget-object v1, p0, Llyiahf/vczjk/vv5;->$transitionState:Llyiahf/vczjk/xc8;

    iget-object v2, p0, Llyiahf/vczjk/vv5;->$backStackEntry:Llyiahf/vczjk/ku5;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/vv5;-><init>(FLlyiahf/vczjk/xc8;Llyiahf/vczjk/ku5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vv5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vv5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vv5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vv5;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v5, :cond_1

    if-ne v1, v4, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget p1, p0, Llyiahf/vczjk/vv5;->$value:F

    cmpl-float v1, p1, v3

    if-lez v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/vv5;->$transitionState:Llyiahf/vczjk/xc8;

    iput v5, p0, Llyiahf/vczjk/vv5;->label:I

    iget-object v5, v1, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v5, Llyiahf/vczjk/fw8;

    invoke-virtual {v5}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v1, p1, v5, p0}, Llyiahf/vczjk/xc8;->OooOOO(FLjava/lang/Object;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_3

    :cond_3
    :goto_0
    iget p1, p0, Llyiahf/vczjk/vv5;->$value:F

    cmpg-float p1, p1, v3

    if-nez p1, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/vv5;->$transitionState:Llyiahf/vczjk/xc8;

    iget-object v1, p0, Llyiahf/vczjk/vv5;->$backStackEntry:Llyiahf/vczjk/ku5;

    iput v4, p0, Llyiahf/vczjk/vv5;->label:I

    iget-object v3, p1, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-nez v3, :cond_5

    :cond_4
    :goto_1
    move-object p1, v2

    goto :goto_2

    :cond_5
    iget-object v4, p1, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    iget-object v4, p1, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    goto :goto_1

    :cond_6
    new-instance v4, Llyiahf/vczjk/uc8;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v1, v3, v5}, Llyiahf/vczjk/uc8;-><init>(Llyiahf/vczjk/xc8;Ljava/lang/Object;Llyiahf/vczjk/bz9;Llyiahf/vczjk/yo1;)V

    iget-object p1, p1, Llyiahf/vczjk/xc8;->OooOO0O:Llyiahf/vczjk/it5;

    invoke-static {p1, v4, p0}, Llyiahf/vczjk/it5;->OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_2
    if-ne p1, v0, :cond_7

    :goto_3
    return-object v0

    :cond_7
    return-object v2
.end method
