.class public final Llyiahf/vczjk/aa5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $mainVM:Llyiahf/vczjk/ua5;

.field final synthetic $props:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ua5;Ljava/util/List;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aa5;->$mainVM:Llyiahf/vczjk/ua5;

    iput-object p2, p0, Llyiahf/vczjk/aa5;->$props:Ljava/util/List;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/aa5;

    iget-object v0, p0, Llyiahf/vczjk/aa5;->$mainVM:Llyiahf/vczjk/ua5;

    iget-object v1, p0, Llyiahf/vczjk/aa5;->$props:Ljava/util/List;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/aa5;-><init>(Llyiahf/vczjk/ua5;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/aa5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/aa5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/aa5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/aa5;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/aa5;->$mainVM:Llyiahf/vczjk/ua5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/la5;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/la5;-><init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v4, v4, v3, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iget-object p1, p0, Llyiahf/vczjk/aa5;->$mainVM:Llyiahf/vczjk/ua5;

    iget-object v1, p0, Llyiahf/vczjk/aa5;->$props:Ljava/util/List;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/ua5;->OooO(Ljava/util/List;Z)V

    iget-object p1, p0, Llyiahf/vczjk/aa5;->$mainVM:Llyiahf/vczjk/ua5;

    iget-object v1, p0, Llyiahf/vczjk/aa5;->$props:Ljava/util/List;

    iput v2, p0, Llyiahf/vczjk/aa5;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/ua5;->OooO0oo(Ljava/util/List;Llyiahf/vczjk/zo1;)V

    return-object v0
.end method
