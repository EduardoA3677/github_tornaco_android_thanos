.class public final Llyiahf/vczjk/nh4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ph4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ph4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nh4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nh4;->OooOOO:Llyiahf/vczjk/ph4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/nh4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/nh4;->OooOOO:Llyiahf/vczjk/ph4;

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->OooOOoo()Ljava/lang/reflect/Member;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/oh4;

    iget-object v1, p0, Llyiahf/vczjk/nh4;->OooOOO:Llyiahf/vczjk/ph4;

    invoke-direct {v0, v1}, Llyiahf/vczjk/oh4;-><init>(Llyiahf/vczjk/ph4;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
