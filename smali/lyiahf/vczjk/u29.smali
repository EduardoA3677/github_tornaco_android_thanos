.class public final Llyiahf/vczjk/u29;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $incomingAnimationSpec:Llyiahf/vczjk/wl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wl;"
        }
    .end annotation
.end field

.field final synthetic $targetAlpha:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/w29;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w29;FLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u29;->this$0:Llyiahf/vczjk/w29;

    iput p2, p0, Llyiahf/vczjk/u29;->$targetAlpha:F

    iput-object p3, p0, Llyiahf/vczjk/u29;->$incomingAnimationSpec:Llyiahf/vczjk/wl;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/u29;

    iget-object v0, p0, Llyiahf/vczjk/u29;->this$0:Llyiahf/vczjk/w29;

    iget v1, p0, Llyiahf/vczjk/u29;->$targetAlpha:F

    iget-object v2, p0, Llyiahf/vczjk/u29;->$incomingAnimationSpec:Llyiahf/vczjk/wl;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/u29;-><init>(Llyiahf/vczjk/w29;FLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u29;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u29;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u29;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u29;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/u29;->this$0:Llyiahf/vczjk/w29;

    iget-object v3, p1, Llyiahf/vczjk/w29;->OooO0OO:Llyiahf/vczjk/gi;

    iget p1, p0, Llyiahf/vczjk/u29;->$targetAlpha:F

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    iget-object v5, p0, Llyiahf/vczjk/u29;->$incomingAnimationSpec:Llyiahf/vczjk/wl;

    iput v2, p0, Llyiahf/vczjk/u29;->label:I

    const/4 v6, 0x0

    const/16 v8, 0xc

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
