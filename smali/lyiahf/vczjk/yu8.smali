.class public final Llyiahf/vczjk/yu8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $onAnimationStep:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $previousValue:Llyiahf/vczjk/el7;

.field final synthetic $targetOffset:F

.field final synthetic $this_animateDecay:Llyiahf/vczjk/v98;


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/el7;Llyiahf/vczjk/v98;Llyiahf/vczjk/su8;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/yu8;->$targetOffset:F

    iput-object p2, p0, Llyiahf/vczjk/yu8;->$previousValue:Llyiahf/vczjk/el7;

    iput-object p3, p0, Llyiahf/vczjk/yu8;->$this_animateDecay:Llyiahf/vczjk/v98;

    iput-object p4, p0, Llyiahf/vczjk/yu8;->$onAnimationStep:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/fl;

    iget-object v0, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    iget v1, p0, Llyiahf/vczjk/yu8;->$targetOffset:F

    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpl-float v0, v0, v1

    iget-object v1, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    if-ltz v0, :cond_0

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget v1, p0, Llyiahf/vczjk/yu8;->$targetOffset:F

    invoke-static {v0, v1}, Llyiahf/vczjk/bv8;->OooO0Oo(FF)F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/yu8;->$previousValue:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    sub-float v1, v0, v1

    iget-object v2, p0, Llyiahf/vczjk/yu8;->$this_animateDecay:Llyiahf/vczjk/v98;

    iget-object v3, p0, Llyiahf/vczjk/yu8;->$onAnimationStep:Llyiahf/vczjk/oe3;

    invoke-static {p1, v2, v3, v1}, Llyiahf/vczjk/bv8;->OooO0O0(Llyiahf/vczjk/fl;Llyiahf/vczjk/v98;Llyiahf/vczjk/oe3;F)V

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/yu8;->$previousValue:Llyiahf/vczjk/el7;

    iput v0, p1, Llyiahf/vczjk/el7;->element:F

    goto :goto_0

    :cond_0
    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/yu8;->$previousValue:Llyiahf/vczjk/el7;

    iget v2, v2, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v0, v2

    iget-object v2, p0, Llyiahf/vczjk/yu8;->$this_animateDecay:Llyiahf/vczjk/v98;

    iget-object v3, p0, Llyiahf/vczjk/yu8;->$onAnimationStep:Llyiahf/vczjk/oe3;

    invoke-static {p1, v2, v3, v0}, Llyiahf/vczjk/bv8;->OooO0O0(Llyiahf/vczjk/fl;Llyiahf/vczjk/v98;Llyiahf/vczjk/oe3;F)V

    iget-object p1, p0, Llyiahf/vczjk/yu8;->$previousValue:Llyiahf/vczjk/el7;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iput v0, p1, Llyiahf/vczjk/el7;->element:F

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
