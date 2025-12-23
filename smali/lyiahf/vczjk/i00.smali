.class public final Llyiahf/vczjk/i00;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/s29;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/s29;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/i00;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/i00;->OooOOO:Llyiahf/vczjk/s29;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/i00;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/wk1;

    invoke-direct {v0, p1}, Llyiahf/vczjk/wk1;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/i00;->OooOOO:Llyiahf/vczjk/s29;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/ci1;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ci1;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/i00;->OooOOO:Llyiahf/vczjk/s29;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/h00;

    invoke-direct {v0, p1}, Llyiahf/vczjk/h00;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/i00;->OooOOO:Llyiahf/vczjk/s29;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
