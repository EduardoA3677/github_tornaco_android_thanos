.class public final Llyiahf/vczjk/kd4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/nd4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nd4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/kd4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/kd4;->OooOOO:Llyiahf/vczjk/nd4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/kd4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/kd4;->OooOOO:Llyiahf/vczjk/nd4;

    iget-object v0, v0, Llyiahf/vczjk/nd4;->OooOOO0:Llyiahf/vczjk/dm5;

    iget-object v0, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/kd4;->OooOOO:Llyiahf/vczjk/nd4;

    iget-object v0, v0, Llyiahf/vczjk/nd4;->OooOOO0:Llyiahf/vczjk/dm5;

    const-string v1, ""

    const-string v2, "WARNING"

    iget-object v0, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    const-string v3, "This member is not fully supported by Kotlin compiler, so it may be absent or have different signature in next major version"

    invoke-static {v0, v3, v1, v2}, Llyiahf/vczjk/ho;->OooO00o(Llyiahf/vczjk/hk4;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/wj0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/po;

    const/4 v2, 0x0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/po;-><init>(ILjava/util/List;)V

    move-object v0, v1

    :goto_0
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
