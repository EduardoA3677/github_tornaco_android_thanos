.class public final Llyiahf/vczjk/bq7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $scrollOffset:F

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/fq7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/fq7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/fq7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/bq7;->$scrollOffset:F

    iput-object p2, p0, Llyiahf/vczjk/bq7;->this$0:Llyiahf/vczjk/fq7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/bq7;

    iget v0, p0, Llyiahf/vczjk/bq7;->$scrollOffset:F

    iget-object v1, p0, Llyiahf/vczjk/bq7;->this$0:Llyiahf/vczjk/fq7;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/bq7;-><init>(FLlyiahf/vczjk/fq7;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bq7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bq7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bq7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/bq7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/bq7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/gl7;

    iget-object v3, p0, Llyiahf/vczjk/bq7;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/el7;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/el7;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iget v1, p0, Llyiahf/vczjk/bq7;->$scrollOffset:F

    iput v1, p1, Llyiahf/vczjk/el7;->element:F

    new-instance v1, Llyiahf/vczjk/gl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    move-object v3, p1

    :goto_0
    iget p1, v3, Llyiahf/vczjk/el7;->element:F

    const/4 v4, 0x0

    cmpg-float p1, p1, v4

    if-nez p1, :cond_2

    goto :goto_2

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/bq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object p1, p1, Llyiahf/vczjk/fq7;->OooOO0:Llyiahf/vczjk/r09;

    if-eqz p1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/k84;->OooO0Oo()Z

    move-result p1

    if-ne p1, v2, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/bq7;->this$0:Llyiahf/vczjk/fq7;

    new-instance v4, Llyiahf/vczjk/oo0ooO;

    const/16 v5, 0x11

    invoke-direct {v4, v1, v3, v5, p1}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iput-object v3, p0, Llyiahf/vczjk/bq7;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/bq7;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/bq7;->label:I

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object p1

    new-instance v5, Llyiahf/vczjk/yn5;

    invoke-direct {v5, v4}, Llyiahf/vczjk/yn5;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {p1, p0, v5}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/bq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object p1, p1, Llyiahf/vczjk/fq7;->OooO0oO:Llyiahf/vczjk/jj0;

    iget v4, v3, Llyiahf/vczjk/el7;->element:F

    new-instance v5, Ljava/lang/Float;

    invoke-direct {v5, v4}, Ljava/lang/Float;-><init>(F)V

    invoke-interface {p1, v5}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
