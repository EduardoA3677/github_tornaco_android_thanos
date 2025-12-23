.class public final synthetic Llyiahf/vczjk/mq2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/nq2;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Landroid/os/Message;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nq2;Landroid/os/Message;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/mq2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/mq2;->OooOOO:Llyiahf/vczjk/nq2;

    iput-object p2, p0, Llyiahf/vczjk/mq2;->OooOOOO:Landroid/os/Message;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/mq2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/mq2;->OooOOO:Llyiahf/vczjk/nq2;

    iget-object v1, p0, Llyiahf/vczjk/mq2;->OooOOOO:Landroid/os/Message;

    invoke-static {v0, v1}, Llyiahf/vczjk/nq2;->OooO0O0(Llyiahf/vczjk/nq2;Landroid/os/Message;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/mq2;->OooOOO:Llyiahf/vczjk/nq2;

    iget-object v1, p0, Llyiahf/vczjk/mq2;->OooOOOO:Landroid/os/Message;

    invoke-static {v0, v1}, Llyiahf/vczjk/nq2;->OooO00o(Llyiahf/vczjk/nq2;Landroid/os/Message;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
