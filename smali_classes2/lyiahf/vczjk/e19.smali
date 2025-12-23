.class public final Llyiahf/vczjk/e19;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/e19;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/e19;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sca;

    iget-object v0, v0, Llyiahf/vczjk/sca;->OooOoOO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/tq2;->Oooo0:Llyiahf/vczjk/tq2;

    iget-object v1, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qx7;

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v0

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i99;

    iget-object v1, v0, Llyiahf/vczjk/i99;->OooO0O0:Llyiahf/vczjk/jg5;

    const/4 v2, 0x0

    const/4 v3, 0x3

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/kh6;->OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/i99;->OooO0oo(Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object v0

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i5a;

    invoke-virtual {v0}, Llyiahf/vczjk/i5a;->OooO0o()Llyiahf/vczjk/g5a;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/i5a;

    invoke-direct {v1, v0}, Llyiahf/vczjk/i5a;-><init>(Llyiahf/vczjk/g5a;)V

    return-object v1

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/e19;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f19;

    iget-object v0, v0, Llyiahf/vczjk/f19;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t4a;

    invoke-static {v0}, Llyiahf/vczjk/tn6;->OooOOo(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/uk4;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
