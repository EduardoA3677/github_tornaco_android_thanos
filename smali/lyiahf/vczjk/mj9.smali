.class public final Llyiahf/vczjk/mj9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $pressedInteraction:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field synthetic J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mj9;->$scope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/mj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/mj9;->$interactionSource:Llyiahf/vczjk/rr5;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/l37;

    check-cast p2, Llyiahf/vczjk/p86;

    iget-wide v0, p2, Llyiahf/vczjk/p86;->OooO00o:J

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance p2, Llyiahf/vczjk/mj9;

    iget-object v2, p0, Llyiahf/vczjk/mj9;->$scope:Llyiahf/vczjk/xr1;

    iget-object v3, p0, Llyiahf/vczjk/mj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iget-object v4, p0, Llyiahf/vczjk/mj9;->$interactionSource:Llyiahf/vczjk/rr5;

    invoke-direct {p2, v2, v3, v4, p3}, Llyiahf/vczjk/mj9;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    iput-object p1, p2, Llyiahf/vczjk/mj9;->L$0:Ljava/lang/Object;

    iput-wide v0, p2, Llyiahf/vczjk/mj9;->J$0:J

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/mj9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mj9;->label:I

    const/4 v2, 0x3

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mj9;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l37;

    iget-wide v7, p0, Llyiahf/vczjk/mj9;->J$0:J

    iget-object v1, p0, Llyiahf/vczjk/mj9;->$scope:Llyiahf/vczjk/xr1;

    new-instance v5, Llyiahf/vczjk/kj9;

    iget-object v6, p0, Llyiahf/vczjk/mj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iget-object v9, p0, Llyiahf/vczjk/mj9;->$interactionSource:Llyiahf/vczjk/rr5;

    const/4 v10, 0x0

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/kj9;-><init>(Llyiahf/vczjk/qs5;JLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v3, v3, v5, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iput v4, p0, Llyiahf/vczjk/mj9;->label:I

    check-cast p1, Llyiahf/vczjk/o37;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/o37;->OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/mj9;->$scope:Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/lj9;

    iget-object v4, p0, Llyiahf/vczjk/mj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iget-object v5, p0, Llyiahf/vczjk/mj9;->$interactionSource:Llyiahf/vczjk/rr5;

    invoke-direct {v1, v4, p1, v5, v3}, Llyiahf/vczjk/lj9;-><init>(Llyiahf/vczjk/qs5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v3, v3, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
