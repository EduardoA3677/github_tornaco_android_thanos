.class public final Llyiahf/vczjk/do5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/animation/Interpolator;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/vz5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/vz5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/do5;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/do5;->OooO0O0:Llyiahf/vczjk/vz5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final getInterpolation(F)F
    .locals 3

    iget v0, p0, Llyiahf/vczjk/do5;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/do5;->OooO0O0:Llyiahf/vczjk/vz5;

    float-to-double v1, p1

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/vz5;->OooO0oo(D)D

    move-result-wide v0

    double-to-float p1, v0

    return p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/do5;->OooO0O0:Llyiahf/vczjk/vz5;

    float-to-double v1, p1

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/vz5;->OooO0oo(D)D

    move-result-wide v0

    double-to-float p1, v0

    return p1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/do5;->OooO0O0:Llyiahf/vczjk/vz5;

    float-to-double v1, p1

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/vz5;->OooO0oo(D)D

    move-result-wide v0

    double-to-float p1, v0

    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
