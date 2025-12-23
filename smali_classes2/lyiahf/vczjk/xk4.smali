.class public final Llyiahf/vczjk/xk4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/n3a;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)V
    .locals 0

    const/4 p2, 0x0

    iput p2, p0, Llyiahf/vczjk/xk4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/xk4;->OooOOO:Llyiahf/vczjk/n3a;

    iput-object p1, p0, Llyiahf/vczjk/xk4;->OooOOOO:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/jg5;Llyiahf/vczjk/d3a;Llyiahf/vczjk/n3a;Z)V
    .locals 0

    const/4 p2, 0x1

    iput p2, p0, Llyiahf/vczjk/xk4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p4, p0, Llyiahf/vczjk/xk4;->OooOOO:Llyiahf/vczjk/n3a;

    iput-object p1, p0, Llyiahf/vczjk/xk4;->OooOOOO:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xk4;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/al4;

    packed-switch v0, :pswitch_data_0

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/xk4;->OooOOO:Llyiahf/vczjk/n3a;

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    const/4 p1, 0x0

    return-object p1

    :pswitch_0
    const-string v0, "refiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/xk4;->OooOOO:Llyiahf/vczjk/n3a;

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    const/4 p1, 0x0

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
