.class public final Llyiahf/vczjk/kp5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $requiredAnimation:Llyiahf/vczjk/dl7;

.field final synthetic $targetScrollDelta:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $targetValue:Llyiahf/vczjk/el7;

.field final synthetic $this_dispatchMouseWheelScroll:Llyiahf/vczjk/db8;

.field final synthetic this$0:Llyiahf/vczjk/tp5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp5;Llyiahf/vczjk/hl7;Llyiahf/vczjk/el7;Llyiahf/vczjk/db8;Llyiahf/vczjk/dl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kp5;->this$0:Llyiahf/vczjk/tp5;

    iput-object p2, p0, Llyiahf/vczjk/kp5;->$targetScrollDelta:Llyiahf/vczjk/hl7;

    iput-object p3, p0, Llyiahf/vczjk/kp5;->$targetValue:Llyiahf/vczjk/el7;

    iput-object p4, p0, Llyiahf/vczjk/kp5;->$this_dispatchMouseWheelScroll:Llyiahf/vczjk/db8;

    iput-object p5, p0, Llyiahf/vczjk/kp5;->$requiredAnimation:Llyiahf/vczjk/dl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/kp5;->this$0:Llyiahf/vczjk/tp5;

    iget-object v0, v0, Llyiahf/vczjk/tp5;->OooO0o0:Llyiahf/vczjk/jj0;

    invoke-static {v0}, Llyiahf/vczjk/tp5;->OooO0Oo(Llyiahf/vczjk/jj0;)Llyiahf/vczjk/fp5;

    move-result-object v0

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/kp5;->this$0:Llyiahf/vczjk/tp5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tp5;->OooO0o0(Llyiahf/vczjk/fp5;)V

    iget-object v2, p0, Llyiahf/vczjk/kp5;->$targetScrollDelta:Llyiahf/vczjk/hl7;

    iget-object v3, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/fp5;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/fp5;->OooO00o(Llyiahf/vczjk/fp5;)Llyiahf/vczjk/fp5;

    move-result-object v3

    iput-object v3, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/kp5;->$targetValue:Llyiahf/vczjk/el7;

    iget-object v3, p0, Llyiahf/vczjk/kp5;->$this_dispatchMouseWheelScroll:Llyiahf/vczjk/db8;

    iget-object v4, p0, Llyiahf/vczjk/kp5;->$targetScrollDelta:Llyiahf/vczjk/hl7;

    iget-object v4, v4, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/fp5;

    iget-wide v4, v4, Llyiahf/vczjk/fp5;->OooO00o:J

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/db8;->OooO0Oo(J)J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result v3

    iput v3, v2, Llyiahf/vczjk/el7;->element:F

    iget-object v2, p0, Llyiahf/vczjk/kp5;->$requiredAnimation:Llyiahf/vczjk/dl7;

    iget-object v3, p0, Llyiahf/vczjk/kp5;->$targetValue:Llyiahf/vczjk/el7;

    iget v3, v3, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v3, p1

    invoke-static {v3}, Llyiahf/vczjk/ep5;->OooO00o(F)Z

    move-result p1

    xor-int/2addr p1, v1

    iput-boolean p1, v2, Llyiahf/vczjk/dl7;->element:Z

    :cond_0
    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
