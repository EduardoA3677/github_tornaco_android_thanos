.class public final Llyiahf/vczjk/bg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $isLeft:Z

.field final synthetic $minTouchTargetSize:J

.field final synthetic $offsetProvider:Llyiahf/vczjk/v86;

.field final synthetic $semanticsModifier:Llyiahf/vczjk/kl5;

.field final synthetic $viewConfiguration:Llyiahf/vczjk/gga;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gga;JZLlyiahf/vczjk/kl5;Llyiahf/vczjk/v86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bg;->$viewConfiguration:Llyiahf/vczjk/gga;

    iput-wide p2, p0, Llyiahf/vczjk/bg;->$minTouchTargetSize:J

    iput-boolean p4, p0, Llyiahf/vczjk/bg;->$isLeft:Z

    iput-object p5, p0, Llyiahf/vczjk/bg;->$semanticsModifier:Llyiahf/vczjk/kl5;

    iput-object p6, p0, Llyiahf/vczjk/bg;->$offsetProvider:Llyiahf/vczjk/v86;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_1

    sget-object p2, Llyiahf/vczjk/ch1;->OooOOoo:Llyiahf/vczjk/l39;

    iget-object v0, p0, Llyiahf/vczjk/bg;->$viewConfiguration:Llyiahf/vczjk/gga;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/ag;

    iget-wide v1, p0, Llyiahf/vczjk/bg;->$minTouchTargetSize:J

    iget-boolean v3, p0, Llyiahf/vczjk/bg;->$isLeft:Z

    iget-object v4, p0, Llyiahf/vczjk/bg;->$semanticsModifier:Llyiahf/vczjk/kl5;

    iget-object v5, p0, Llyiahf/vczjk/bg;->$offsetProvider:Llyiahf/vczjk/v86;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ag;-><init>(JZLlyiahf/vczjk/kl5;Llyiahf/vczjk/v86;)V

    const v1, 0x4b1ac501    # 1.0142977E7f

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
