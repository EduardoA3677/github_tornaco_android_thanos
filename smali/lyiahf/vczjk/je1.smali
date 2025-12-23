.class public final synthetic Llyiahf/vczjk/je1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/os/CancellationSignal$OnCancelListener;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/je1;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/je1;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onCancel()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/je1;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/je1;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mk9;

    if-eqz v0, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    sget-wide v2, Llyiahf/vczjk/gn9;->OooO0O0:J

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/lx4;->OooO0o0(J)V

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    sget-wide v1, Llyiahf/vczjk/gn9;->OooO0O0:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/lx4;->OooO0o(J)V

    :cond_2
    :goto_1
    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/je1;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r09;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
