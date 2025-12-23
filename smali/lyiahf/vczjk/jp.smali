.class public final synthetic Llyiahf/vczjk/jp;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kx9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kx9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/jp;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/jp;->OooOOO:Llyiahf/vczjk/kx9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/jp;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/fl;

    iget-object p1, p1, Llyiahf/vczjk/fl;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/jp;->OooOOO:Llyiahf/vczjk/kx9;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/kx9;->OooO0Oo(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int p1, v0

    int-to-float p1, p1

    iget-object v0, p0, Llyiahf/vczjk/jp;->OooOOO:Llyiahf/vczjk/kx9;

    invoke-virtual {v0}, Llyiahf/vczjk/kx9;->OooO0O0()F

    move-result v1

    sub-float/2addr p1, v1

    neg-float p1, p1

    iput p1, v0, Llyiahf/vczjk/kx9;->OooO00o:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
