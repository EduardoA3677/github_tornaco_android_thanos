.class public final Llyiahf/vczjk/ic9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $delta:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ic9;->this$0:Llyiahf/vczjk/jc9;

    iput p2, p0, Llyiahf/vczjk/ic9;->$delta:F

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ic9;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ic9;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ic9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ic9;

    iget-object v1, p0, Llyiahf/vczjk/ic9;->this$0:Llyiahf/vczjk/jc9;

    iget v2, p0, Llyiahf/vczjk/ic9;->$delta:F

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/ic9;-><init>(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ic9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ic9;->this$0:Llyiahf/vczjk/jc9;

    iget-object p1, p1, Llyiahf/vczjk/jc9;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {p1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget v3, p0, Llyiahf/vczjk/ic9;->$delta:F

    add-float/2addr v1, v3

    new-instance v3, Ljava/lang/Float;

    invoke-direct {v3, v1}, Ljava/lang/Float;-><init>(F)V

    iput v2, p0, Llyiahf/vczjk/ic9;->label:I

    invoke-virtual {p1, v3, p0}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
