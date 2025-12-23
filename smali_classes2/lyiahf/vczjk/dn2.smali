.class public final Llyiahf/vczjk/dn2;
.super Llyiahf/vczjk/ih6;
.source "SourceFile"


# instance fields
.field public final synthetic OooOo0O:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/dn2;->OooOo0O:I

    packed-switch p3, :pswitch_data_0

    const-string p3, "module"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "fqName"

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ih6;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V

    return-void

    :pswitch_0
    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ih6;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final bridge synthetic OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/dn2;->OooOo0O:I

    packed-switch v0, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
