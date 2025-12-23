.class public final Llyiahf/vczjk/lj9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $pressedInteraction:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $success:Z

.field L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iput-boolean p2, p0, Llyiahf/vczjk/lj9;->$success:Z

    iput-object p3, p0, Llyiahf/vczjk/lj9;->$interactionSource:Llyiahf/vczjk/rr5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/lj9;

    iget-object v0, p0, Llyiahf/vczjk/lj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    iget-boolean v1, p0, Llyiahf/vczjk/lj9;->$success:Z

    iget-object v2, p0, Llyiahf/vczjk/lj9;->$interactionSource:Llyiahf/vczjk/rr5;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/lj9;-><init>(Llyiahf/vczjk/qs5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lj9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lj9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lj9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/lj9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/lj9;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/lj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/q37;

    if-eqz p1, :cond_5

    iget-boolean v1, p0, Llyiahf/vczjk/lj9;->$success:Z

    iget-object v3, p0, Llyiahf/vczjk/lj9;->$interactionSource:Llyiahf/vczjk/rr5;

    iget-object v4, p0, Llyiahf/vczjk/lj9;->$pressedInteraction:Llyiahf/vczjk/qs5;

    if-eqz v1, :cond_2

    new-instance v1, Llyiahf/vczjk/r37;

    invoke-direct {v1, p1}, Llyiahf/vczjk/r37;-><init>(Llyiahf/vczjk/q37;)V

    goto :goto_0

    :cond_2
    new-instance v1, Llyiahf/vczjk/p37;

    invoke-direct {v1, p1}, Llyiahf/vczjk/p37;-><init>(Llyiahf/vczjk/q37;)V

    :goto_0
    if-eqz v3, :cond_4

    iput-object v4, p0, Llyiahf/vczjk/lj9;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/lj9;->label:I

    check-cast v3, Llyiahf/vczjk/sr5;

    invoke-virtual {v3, v1, p0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    move-object v0, v4

    :goto_1
    move-object v4, v0

    :cond_4
    const/4 p1, 0x0

    invoke-interface {v4, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
