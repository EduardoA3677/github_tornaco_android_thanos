.class public final Llyiahf/vczjk/qr4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/rr4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/rr4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/qr4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qr4;->OooOOO:Llyiahf/vczjk/rr4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/qr4;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/qt5;

    packed-switch v0, :pswitch_data_0

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qr4;->OooOOO:Llyiahf/vczjk/rr4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rr4;->Oooo0oo(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1

    :pswitch_0
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/qr4;->OooOOO:Llyiahf/vczjk/rr4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rr4;->Oooo0oO(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
