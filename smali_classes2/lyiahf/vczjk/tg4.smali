.class public final Llyiahf/vczjk/tg4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/yg4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/yg4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tg4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/tg4;->OooOOO:Llyiahf/vczjk/yg4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tg4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/tg4;->OooOOO:Llyiahf/vczjk/yg4;

    iget-object v0, v0, Llyiahf/vczjk/yg4;->OooOOO:Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/eo6;->OooO0oo(Ljava/lang/Class;)Llyiahf/vczjk/tm7;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/wg4;

    iget-object v1, p0, Llyiahf/vczjk/tg4;->OooOOO:Llyiahf/vczjk/yg4;

    invoke-direct {v0, v1}, Llyiahf/vczjk/wg4;-><init>(Llyiahf/vczjk/yg4;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
