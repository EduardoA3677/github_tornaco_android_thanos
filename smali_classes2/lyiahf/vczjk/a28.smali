.class public final Llyiahf/vczjk/a28;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/s29;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/f28;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/s29;Llyiahf/vczjk/f28;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/a28;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/a28;->OooOOO:Llyiahf/vczjk/s29;

    iput-object p2, p0, Llyiahf/vczjk/a28;->OooOOOO:Llyiahf/vczjk/f28;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/a28;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/d28;

    iget-object v1, p0, Llyiahf/vczjk/a28;->OooOOOO:Llyiahf/vczjk/f28;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/d28;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/f28;)V

    iget-object p1, p0, Llyiahf/vczjk/a28;->OooOOO:Llyiahf/vczjk/s29;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/z18;

    iget-object v1, p0, Llyiahf/vczjk/a28;->OooOOOO:Llyiahf/vczjk/f28;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/z18;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/f28;)V

    iget-object p1, p0, Llyiahf/vczjk/a28;->OooOOO:Llyiahf/vczjk/s29;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/s29;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
