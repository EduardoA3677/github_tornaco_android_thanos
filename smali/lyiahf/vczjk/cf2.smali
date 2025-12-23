.class public final Llyiahf/vczjk/cf2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

.field final synthetic $velocityTracker:Llyiahf/vczjk/hea;

.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hea;Llyiahf/vczjk/oy6;Llyiahf/vczjk/kf2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cf2;->$velocityTracker:Llyiahf/vczjk/hea;

    iput-object p2, p0, Llyiahf/vczjk/cf2;->$this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

    iput-object p3, p0, Llyiahf/vczjk/cf2;->this$0:Llyiahf/vczjk/kf2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/ky6;

    iget-object v0, p0, Llyiahf/vczjk/cf2;->$velocityTracker:Llyiahf/vczjk/hea;

    invoke-static {v0, p1}, Llyiahf/vczjk/ok6;->OooOOOo(Llyiahf/vczjk/hea;Llyiahf/vczjk/ky6;)V

    iget-object p1, p0, Llyiahf/vczjk/cf2;->$this_SuspendingPointerInputModifierNode:Llyiahf/vczjk/oy6;

    check-cast p1, Llyiahf/vczjk/nb9;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    invoke-interface {p1}, Llyiahf/vczjk/gga;->OooO0o0()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/cf2;->$velocityTracker:Llyiahf/vczjk/hea;

    invoke-static {p1, p1}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v2}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result p1

    const/4 v3, 0x0

    cmpl-float p1, p1, v3

    if-lez p1, :cond_0

    invoke-static {v1, v2}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result p1

    cmpl-float p1, p1, v3

    if-lez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v4, "maximumVelocity should be a positive value. You specified="

    invoke-direct {p1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v1, v2}, Llyiahf/vczjk/fea;->OooO0oO(J)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/hea;->OooO00o:Llyiahf/vczjk/fv7;

    invoke-static {v1, v2}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result v4

    invoke-virtual {p1, v4}, Llyiahf/vczjk/fv7;->OooO0O0(F)F

    move-result p1

    iget-object v0, v0, Llyiahf/vczjk/hea;->OooO0O0:Llyiahf/vczjk/fv7;

    invoke-static {v1, v2}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fv7;->OooO0O0(F)F

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/cf2;->$velocityTracker:Llyiahf/vczjk/hea;

    iget-object v2, p1, Llyiahf/vczjk/hea;->OooO00o:Llyiahf/vczjk/fv7;

    iget-object v4, v2, Llyiahf/vczjk/fv7;->OooO0o0:Ljava/lang/Object;

    check-cast v4, [Llyiahf/vczjk/wx1;

    const/4 v5, 0x0

    invoke-static {v4, v5}, Llyiahf/vczjk/sy;->o0Oo0oo([Ljava/lang/Object;Llyiahf/vczjk/h87;)V

    const/4 v4, 0x0

    iput v4, v2, Llyiahf/vczjk/fv7;->OooO0OO:I

    iget-object v2, p1, Llyiahf/vczjk/hea;->OooO0O0:Llyiahf/vczjk/fv7;

    iget-object v6, v2, Llyiahf/vczjk/fv7;->OooO0o0:Ljava/lang/Object;

    check-cast v6, [Llyiahf/vczjk/wx1;

    invoke-static {v6, v5}, Llyiahf/vczjk/sy;->o0Oo0oo([Ljava/lang/Object;Llyiahf/vczjk/h87;)V

    iput v4, v2, Llyiahf/vczjk/fv7;->OooO0OO:I

    const-wide/16 v4, 0x0

    iput-wide v4, p1, Llyiahf/vczjk/hea;->OooO0OO:J

    iget-object p1, p0, Llyiahf/vczjk/cf2;->this$0:Llyiahf/vczjk/kf2;

    iget-object p1, p1, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    if-eqz p1, :cond_3

    new-instance v2, Llyiahf/vczjk/me2;

    sget-object v4, Llyiahf/vczjk/uf2;->OooO00o:Llyiahf/vczjk/rf2;

    invoke-static {v0, v1}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    move-result v4

    if-eqz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    invoke-static {v0, v1}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result v4

    :goto_1
    invoke-static {v0, v1}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v5

    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    move-result v5

    if-eqz v5, :cond_2

    goto :goto_2

    :cond_2
    invoke-static {v0, v1}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v3

    :goto_2
    invoke-static {v4, v3}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide v0

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/me2;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
