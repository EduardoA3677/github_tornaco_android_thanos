.class public final Llyiahf/vczjk/ia2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $dialogNavigator:Llyiahf/vczjk/za2;

.field final synthetic $dialogsToDispose:Llyiahf/vczjk/tw8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tw8;"
        }
    .end annotation
.end field

.field final synthetic $transitionInProgress$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/za2;Llyiahf/vczjk/tw8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ia2;->$transitionInProgress$delegate:Llyiahf/vczjk/p29;

    iput-object p2, p0, Llyiahf/vczjk/ia2;->$dialogNavigator:Llyiahf/vczjk/za2;

    iput-object p3, p0, Llyiahf/vczjk/ia2;->$dialogsToDispose:Llyiahf/vczjk/tw8;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/ia2;

    iget-object v0, p0, Llyiahf/vczjk/ia2;->$transitionInProgress$delegate:Llyiahf/vczjk/p29;

    iget-object v1, p0, Llyiahf/vczjk/ia2;->$dialogNavigator:Llyiahf/vczjk/za2;

    iget-object v2, p0, Llyiahf/vczjk/ia2;->$dialogsToDispose:Llyiahf/vczjk/tw8;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/ia2;-><init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/za2;Llyiahf/vczjk/tw8;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ia2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ia2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ia2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/ia2;->label:I

    if-nez v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ia2;->$transitionInProgress$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Set;

    check-cast p1, Ljava/lang/Iterable;

    iget-object v0, p0, Llyiahf/vczjk/ia2;->$dialogNavigator:Llyiahf/vczjk/za2;

    iget-object v1, p0, Llyiahf/vczjk/ia2;->$dialogsToDispose:Llyiahf/vczjk/tw8;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ku5;

    invoke-virtual {v0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v3

    iget-object v3, v3, Llyiahf/vczjk/pu5;->OooO0o0:Llyiahf/vczjk/gh7;

    iget-object v3, v3, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v3, Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    invoke-interface {v3, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {v1, v2}, Llyiahf/vczjk/tw8;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v3

    invoke-virtual {v3, v2}, Llyiahf/vczjk/pu5;->OooO0OO(Llyiahf/vczjk/ku5;)V

    goto :goto_0

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
