.class public final Llyiahf/vczjk/u76;
.super Llyiahf/vczjk/oo0o0O0;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/o76;Ljava/lang/Object;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/u76;->OooOOO:I

    invoke-direct {p0, p1}, Llyiahf/vczjk/oo0o0O0;-><init>(Llyiahf/vczjk/o76;)V

    iput-object p2, p0, Llyiahf/vczjk/u76;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/u76;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/f86;

    invoke-direct {v0, p1}, Llyiahf/vczjk/f86;-><init>(Llyiahf/vczjk/j86;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    new-instance p1, Llyiahf/vczjk/js2;

    const/16 v1, 0xd

    invoke-direct {p1, v1, p0, v0}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/u76;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/i88;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/i88;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/r76;

    iget-object v1, p0, Llyiahf/vczjk/u76;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/c17;

    const/4 v2, 0x1

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/r76;-><init>(Llyiahf/vczjk/j86;Ljava/lang/Object;I)V

    iget-object p1, p0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/t76;

    iget-object v1, p0, Llyiahf/vczjk/u76;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/nl1;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/t76;-><init>(Llyiahf/vczjk/j86;Llyiahf/vczjk/nl1;)V

    iget-object p1, p0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
