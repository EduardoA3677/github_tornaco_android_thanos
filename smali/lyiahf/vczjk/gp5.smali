.class public final Llyiahf/vczjk/gp5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $lastValue:Llyiahf/vczjk/el7;

.field final synthetic $shouldCancelAnimation:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $this_animateMouseWheelScroll:Llyiahf/vczjk/lz5;

.field final synthetic this$0:Llyiahf/vczjk/tp5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/tp5;Llyiahf/vczjk/lz5;Llyiahf/vczjk/kp5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gp5;->$lastValue:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/gp5;->this$0:Llyiahf/vczjk/tp5;

    iput-object p3, p0, Llyiahf/vczjk/gp5;->$this_animateMouseWheelScroll:Llyiahf/vczjk/lz5;

    iput-object p4, p0, Llyiahf/vczjk/gp5;->$shouldCancelAnimation:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/fl;

    iget-object v0, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/gp5;->$lastValue:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v0, v1

    invoke-static {v0}, Llyiahf/vczjk/ep5;->OooO00o(F)Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/gp5;->this$0:Llyiahf/vczjk/tp5;

    iget-object v2, p0, Llyiahf/vczjk/gp5;->$this_animateMouseWheelScroll:Llyiahf/vczjk/lz5;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/tp5;->OooO00o(Llyiahf/vczjk/tp5;Llyiahf/vczjk/lz5;F)F

    move-result v1

    sub-float v1, v0, v1

    invoke-static {v1}, Llyiahf/vczjk/ep5;->OooO00o(F)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/gp5;->$lastValue:Llyiahf/vczjk/el7;

    iget v2, v1, Llyiahf/vczjk/el7;->element:F

    add-float/2addr v2, v0

    iput v2, v1, Llyiahf/vczjk/el7;->element:F

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/gp5;->$shouldCancelAnimation:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/gp5;->$lastValue:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
