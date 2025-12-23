.class public final Llyiahf/vczjk/n08;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $pagerState:Llyiahf/vczjk/lm6;

.field final synthetic $pkgSets$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $sfVM:Llyiahf/vczjk/h48;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/h48;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/n08;->$pagerState:Llyiahf/vczjk/lm6;

    iput-object p2, p0, Llyiahf/vczjk/n08;->$sfVM:Llyiahf/vczjk/h48;

    iput-object p3, p0, Llyiahf/vczjk/n08;->$pkgSets$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/n08;

    iget-object v0, p0, Llyiahf/vczjk/n08;->$pagerState:Llyiahf/vczjk/lm6;

    iget-object v1, p0, Llyiahf/vczjk/n08;->$sfVM:Llyiahf/vczjk/h48;

    iget-object v2, p0, Llyiahf/vczjk/n08;->$pkgSets$delegate:Llyiahf/vczjk/p29;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/n08;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/h48;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n08;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n08;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/n08;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/n08;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/n08;->$pagerState:Llyiahf/vczjk/lm6;

    new-instance v1, Llyiahf/vczjk/ku7;

    const/4 v4, 0x2

    invoke-direct {v1, p1, v4}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/ow;

    const/16 v4, 0x1b

    invoke-direct {v1, v4}, Llyiahf/vczjk/ow;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/g53;

    const/4 v5, 0x0

    invoke-direct {v4, v1, p1, v5}, Llyiahf/vczjk/g53;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/tx3;

    iget-object v1, p0, Llyiahf/vczjk/n08;->$sfVM:Llyiahf/vczjk/h48;

    iget-object v6, p0, Llyiahf/vczjk/n08;->$pkgSets$delegate:Llyiahf/vczjk/p29;

    const/4 v7, 0x7

    invoke-direct {p1, v7, v1, v6}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput v3, p0, Llyiahf/vczjk/n08;->label:I

    new-instance v1, Llyiahf/vczjk/j43;

    invoke-direct {v1, v4, p1, v5}, Llyiahf/vczjk/j43;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p0}, Llyiahf/vczjk/vc6;->OooOo0O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v1, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    return-object v2
.end method
