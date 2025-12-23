.class public final Llyiahf/vczjk/xt8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/wl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/wl;"
        }
    .end annotation
.end field

.field final synthetic $scale:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $visible:Z

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xt8;->$scale:Llyiahf/vczjk/gi;

    iput-boolean p2, p0, Llyiahf/vczjk/xt8;->$visible:Z

    iput-object p3, p0, Llyiahf/vczjk/xt8;->$animation:Llyiahf/vczjk/wl;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/xt8;

    iget-object v0, p0, Llyiahf/vczjk/xt8;->$scale:Llyiahf/vczjk/gi;

    iget-boolean v1, p0, Llyiahf/vczjk/xt8;->$visible:Z

    iget-object v2, p0, Llyiahf/vczjk/xt8;->$animation:Llyiahf/vczjk/wl;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/xt8;-><init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xt8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xt8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/xt8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/xt8;->label:I

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

    iget-object v1, p0, Llyiahf/vczjk/xt8;->$scale:Llyiahf/vczjk/gi;

    iget-boolean p1, p0, Llyiahf/vczjk/xt8;->$visible:Z

    if-eqz p1, :cond_2

    const/high16 p1, 0x3f800000    # 1.0f

    :goto_0
    move v3, v2

    goto :goto_1

    :cond_2
    const p1, 0x3f4ccccd    # 0.8f

    goto :goto_0

    :goto_1
    new-instance v2, Ljava/lang/Float;

    invoke-direct {v2, p1}, Ljava/lang/Float;-><init>(F)V

    move p1, v3

    iget-object v3, p0, Llyiahf/vczjk/xt8;->$animation:Llyiahf/vczjk/wl;

    iput p1, p0, Llyiahf/vczjk/xt8;->label:I

    const/4 v4, 0x0

    const/16 v6, 0xc

    move-object v5, p0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
