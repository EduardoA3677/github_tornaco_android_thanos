.class public final Llyiahf/vczjk/n82;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/le3;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/n82;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/n82;->OooOOO:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/n82;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n82;->OooOOO:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jg5;

    instance-of v1, v0, Llyiahf/vczjk/pw4;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/pw4;

    invoke-virtual {v0}, Llyiahf/vczjk/pw4;->OooO0oo()Llyiahf/vczjk/jg5;

    move-result-object v0

    :cond_0
    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n82;->OooOOO:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
