.class public final Llyiahf/vczjk/d22;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $lastValue:Llyiahf/vczjk/el7;

.field final synthetic $this_performFling:Llyiahf/vczjk/v98;

.field final synthetic $velocityLeft:Llyiahf/vczjk/el7;

.field final synthetic this$0:Llyiahf/vczjk/f22;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/v98;Llyiahf/vczjk/el7;Llyiahf/vczjk/f22;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d22;->$lastValue:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/d22;->$this_performFling:Llyiahf/vczjk/v98;

    iput-object p3, p0, Llyiahf/vczjk/d22;->$velocityLeft:Llyiahf/vczjk/el7;

    iput-object p4, p0, Llyiahf/vczjk/d22;->this$0:Llyiahf/vczjk/f22;

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

    iget-object v1, p0, Llyiahf/vczjk/d22;->$lastValue:Llyiahf/vczjk/el7;

    iget v1, v1, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v0, v1

    iget-object v1, p0, Llyiahf/vczjk/d22;->$this_performFling:Llyiahf/vczjk/v98;

    invoke-interface {v1, v0}, Llyiahf/vczjk/v98;->OooO00o(F)F

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/d22;->$lastValue:Llyiahf/vczjk/el7;

    iget-object v3, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    iput v3, v2, Llyiahf/vczjk/el7;->element:F

    iget-object v2, p0, Llyiahf/vczjk/d22;->$velocityLeft:Llyiahf/vczjk/el7;

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    iput v3, v2, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    const/high16 v1, 0x3f000000    # 0.5f

    cmpl-float v0, v0, v1

    if-lez v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/d22;->this$0:Llyiahf/vczjk/f22;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
