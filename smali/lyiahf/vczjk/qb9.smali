.class public final Llyiahf/vczjk/qb9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $indicatorHeight:I

.field final synthetic $offset$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $refreshingOffsetPx:F

.field final synthetic $state:Llyiahf/vczjk/jc9;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jc9;IFLlyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qb9;->$state:Llyiahf/vczjk/jc9;

    iput p2, p0, Llyiahf/vczjk/qb9;->$indicatorHeight:I

    iput p3, p0, Llyiahf/vczjk/qb9;->$refreshingOffsetPx:F

    iput-object p4, p0, Llyiahf/vczjk/qb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/qb9;

    iget-object v1, p0, Llyiahf/vczjk/qb9;->$state:Llyiahf/vczjk/jc9;

    iget v2, p0, Llyiahf/vczjk/qb9;->$indicatorHeight:I

    iget v3, p0, Llyiahf/vczjk/qb9;->$refreshingOffsetPx:F

    iget-object v4, p0, Llyiahf/vczjk/qb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/qb9;-><init>(Llyiahf/vczjk/jc9;IFLlyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qb9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qb9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qb9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qb9;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/qb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    sget-object v1, Llyiahf/vczjk/vb9;->OooO00o:Llyiahf/vczjk/wb9;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result v3

    iget-object p1, p0, Llyiahf/vczjk/qb9;->$state:Llyiahf/vczjk/jc9;

    invoke-virtual {p1}, Llyiahf/vczjk/jc9;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_2

    iget p1, p0, Llyiahf/vczjk/qb9;->$indicatorHeight:I

    int-to-float p1, p1

    iget v1, p0, Llyiahf/vczjk/qb9;->$refreshingOffsetPx:F

    add-float/2addr p1, v1

    :goto_0
    move v4, p1

    goto :goto_1

    :cond_2
    const/4 p1, 0x0

    goto :goto_0

    :goto_1
    new-instance v6, Llyiahf/vczjk/pb9;

    iget-object p1, p0, Llyiahf/vczjk/qb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {v6, p1}, Llyiahf/vczjk/pb9;-><init>(Llyiahf/vczjk/qs5;)V

    iput v2, p0, Llyiahf/vczjk/qb9;->label:I

    const/4 v5, 0x0

    const/16 v8, 0xc

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/vc6;->OooOO0(FFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
