.class public final synthetic Llyiahf/vczjk/c31;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/function/DoubleUnaryOperator;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/rm4;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/rm4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c31;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/c31;->OooO0O0:Llyiahf/vczjk/rm4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final applyAsDouble(D)D
    .locals 1

    iget v0, p0, Llyiahf/vczjk/c31;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/c31;->OooO0O0:Llyiahf/vczjk/rm4;

    check-cast p2, Llyiahf/vczjk/mt7;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/mt7;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide p1

    return-wide p1

    :pswitch_0
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/c31;->OooO0O0:Llyiahf/vczjk/rm4;

    check-cast p2, Llyiahf/vczjk/nt7;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/nt7;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide p1

    return-wide p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
