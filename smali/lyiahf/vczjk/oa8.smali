.class public final Llyiahf/vczjk/oa8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $x:F

.field final synthetic $y:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ra8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ra8;FFLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oa8;->this$0:Llyiahf/vczjk/ra8;

    iput p2, p0, Llyiahf/vczjk/oa8;->$x:F

    iput p3, p0, Llyiahf/vczjk/oa8;->$y:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/oa8;

    iget-object v0, p0, Llyiahf/vczjk/oa8;->this$0:Llyiahf/vczjk/ra8;

    iget v1, p0, Llyiahf/vczjk/oa8;->$x:F

    iget v2, p0, Llyiahf/vczjk/oa8;->$y:F

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/oa8;-><init>(Llyiahf/vczjk/ra8;FFLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/oa8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oa8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/oa8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/oa8;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/oa8;->this$0:Llyiahf/vczjk/ra8;

    iget-object p1, p1, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iget v1, p0, Llyiahf/vczjk/oa8;->$x:F

    iget v3, p0, Llyiahf/vczjk/oa8;->$y:F

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v6, v1

    const/16 v1, 0x20

    shl-long v3, v4, v1

    const-wide v8, 0xffffffffL

    and-long v5, v6, v8

    or-long/2addr v3, v5

    iput v2, p0, Llyiahf/vczjk/oa8;->label:I

    invoke-static {p1, v3, v4, p0}, Landroidx/compose/foundation/gestures/OooO0O0;->OooO00o(Llyiahf/vczjk/db8;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
