.class public final synthetic Llyiahf/vczjk/tl8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/f62;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:F


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/f62;FI)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/tl8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/tl8;->OooOOO:Llyiahf/vczjk/f62;

    iput p2, p0, Llyiahf/vczjk/tl8;->OooOOOO:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tl8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/tl8;->OooOOO:Llyiahf/vczjk/f62;

    iget v1, p0, Llyiahf/vczjk/tl8;->OooOOOO:F

    invoke-interface {v0, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/tl8;->OooOOO:Llyiahf/vczjk/f62;

    iget v1, p0, Llyiahf/vczjk/tl8;->OooOOOO:F

    invoke-interface {v0, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
