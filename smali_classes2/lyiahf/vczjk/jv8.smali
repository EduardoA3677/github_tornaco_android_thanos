.class public final Llyiahf/vczjk/jv8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $lastValue:Llyiahf/vczjk/el7;

.field final synthetic $targetIndex:I

.field final synthetic $this_performSpringFling:Llyiahf/vczjk/v98;

.field final synthetic $velocityLeft:Llyiahf/vczjk/el7;

.field final synthetic this$0:Llyiahf/vczjk/kv8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/el7;Llyiahf/vczjk/v98;Llyiahf/vczjk/el7;Llyiahf/vczjk/kv8;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jv8;->$lastValue:Llyiahf/vczjk/el7;

    iput-object p2, p0, Llyiahf/vczjk/jv8;->$this_performSpringFling:Llyiahf/vczjk/v98;

    iput-object p3, p0, Llyiahf/vczjk/jv8;->$velocityLeft:Llyiahf/vczjk/el7;

    iput-object p4, p0, Llyiahf/vczjk/jv8;->this$0:Llyiahf/vczjk/kv8;

    iput p5, p0, Llyiahf/vczjk/jv8;->$targetIndex:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    check-cast p1, Llyiahf/vczjk/fl;

    const-string v0, "$this$animateTo"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/jv8;->$lastValue:Llyiahf/vczjk/el7;

    iget v2, v2, Llyiahf/vczjk/el7;->element:F

    sub-float/2addr v1, v2

    iget-object v2, p0, Llyiahf/vczjk/jv8;->$this_performSpringFling:Llyiahf/vczjk/v98;

    invoke-interface {v2, v1}, Llyiahf/vczjk/v98;->OooO00o(F)F

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/jv8;->$lastValue:Llyiahf/vczjk/el7;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iput v0, v3, Llyiahf/vczjk/el7;->element:F

    iget-object v0, p0, Llyiahf/vczjk/jv8;->$velocityLeft:Llyiahf/vczjk/el7;

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    iput v3, v0, Llyiahf/vczjk/el7;->element:F

    iget-object v0, p0, Llyiahf/vczjk/jv8;->this$0:Llyiahf/vczjk/kv8;

    iget-object v0, v0, Llyiahf/vczjk/kv8;->OooO00o:Llyiahf/vczjk/xv4;

    invoke-virtual {v0}, Llyiahf/vczjk/xv4;->OooO0o0()Llyiahf/vczjk/yv4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    goto :goto_0

    :cond_0
    iget-object v3, p0, Llyiahf/vczjk/jv8;->this$0:Llyiahf/vczjk/kv8;

    iget v4, p0, Llyiahf/vczjk/jv8;->$targetIndex:I

    new-instance v5, Llyiahf/vczjk/o00000;

    iget-object v7, p0, Llyiahf/vczjk/jv8;->$this_performSpringFling:Llyiahf/vczjk/v98;

    const-string v10, "scrollBy(F)F"

    const/4 v11, 0x0

    const/4 v6, 0x1

    const-class v8, Llyiahf/vczjk/v98;

    const-string v9, "scrollBy"

    const/16 v12, 0xd

    invoke-direct/range {v5 .. v12}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    invoke-static {v3, p1, v0, v4, v5}, Llyiahf/vczjk/kv8;->OooO0O0(Llyiahf/vczjk/kv8;Llyiahf/vczjk/fl;Llyiahf/vczjk/yv4;ILlyiahf/vczjk/oe3;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    goto :goto_0

    :cond_1
    sub-float/2addr v1, v2

    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v0

    const/high16 v1, 0x3f000000    # 0.5f

    cmpl-float v0, v0, v1

    if-lez v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/fl;->OooO00o()V

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
