.class public final Llyiahf/vczjk/c75;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $cancellationBehavior:Llyiahf/vczjk/x75;

.field final synthetic $iteration:I

.field final synthetic $iterations:I

.field final synthetic $parentJob:Llyiahf/vczjk/v74;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/k75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x75;Llyiahf/vczjk/v74;IILlyiahf/vczjk/k75;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    iput-object p2, p0, Llyiahf/vczjk/c75;->$parentJob:Llyiahf/vczjk/v74;

    iput p3, p0, Llyiahf/vczjk/c75;->$iterations:I

    iput p4, p0, Llyiahf/vczjk/c75;->$iteration:I

    iput-object p5, p0, Llyiahf/vczjk/c75;->this$0:Llyiahf/vczjk/k75;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/c75;

    iget-object v1, p0, Llyiahf/vczjk/c75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    iget-object v2, p0, Llyiahf/vczjk/c75;->$parentJob:Llyiahf/vczjk/v74;

    iget v3, p0, Llyiahf/vczjk/c75;->$iterations:I

    iget v4, p0, Llyiahf/vczjk/c75;->$iteration:I

    iget-object v5, p0, Llyiahf/vczjk/c75;->this$0:Llyiahf/vczjk/k75;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/c75;-><init>(Llyiahf/vczjk/x75;Llyiahf/vczjk/v74;IILlyiahf/vczjk/k75;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/c75;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c75;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/c75;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/c75;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/c75;->$cancellationBehavior:Llyiahf/vczjk/x75;

    sget-object v1, Llyiahf/vczjk/b75;->OooO00o:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v1, p1

    if-ne p1, v2, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/c75;->$parentJob:Llyiahf/vczjk/v74;

    invoke-interface {p1}, Llyiahf/vczjk/v74;->OooO0Oo()Z

    move-result p1

    if-eqz p1, :cond_3

    iget p1, p0, Llyiahf/vczjk/c75;->$iterations:I

    goto :goto_0

    :cond_3
    iget p1, p0, Llyiahf/vczjk/c75;->$iteration:I

    goto :goto_0

    :cond_4
    iget p1, p0, Llyiahf/vczjk/c75;->$iterations:I

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/c75;->this$0:Llyiahf/vczjk/k75;

    iput v2, p0, Llyiahf/vczjk/c75;->label:I

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const v3, 0x7fffffff

    if-ne p1, v3, :cond_5

    new-instance v3, Llyiahf/vczjk/e75;

    invoke-direct {v3, v1, p1}, Llyiahf/vczjk/e75;-><init>(Llyiahf/vczjk/k75;I)V

    invoke-static {v3, p0}, Llyiahf/vczjk/sb;->OoooOOo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_1

    :cond_5
    new-instance v3, Llyiahf/vczjk/f75;

    invoke-direct {v3, v1, p1}, Llyiahf/vczjk/f75;-><init>(Llyiahf/vczjk/k75;I)V

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object p1

    invoke-interface {p1, p0, v3}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    :goto_1
    if-ne p1, v0, :cond_6

    return-object v0

    :cond_6
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_2

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
