.class public final Llyiahf/vczjk/g69;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d62;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/g69;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/bh9;Llyiahf/vczjk/bh9;I)V
    .locals 2

    iget p3, p0, Llyiahf/vczjk/g69;->OooO00o:I

    packed-switch p3, :pswitch_data_0

    new-instance p3, Llyiahf/vczjk/vc9;

    invoke-direct {p3}, Llyiahf/vczjk/ak1;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ak1;

    :goto_0
    if-eqz v0, :cond_0

    if-eq v0, p2, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ak1;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/ak1;->OooO0O0(Llyiahf/vczjk/ak1;)V

    move-object v0, v1

    goto :goto_0

    :cond_0
    invoke-virtual {p1, p3}, Llyiahf/vczjk/ak1;->OooO0o0(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_0
    new-instance p3, Llyiahf/vczjk/f69;

    invoke-direct {p3}, Llyiahf/vczjk/ak1;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ak1;

    :goto_1
    if-eqz v0, :cond_1

    if-eq v0, p2, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ak1;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/ak1;->OooO0O0(Llyiahf/vczjk/ak1;)V

    move-object v0, v1

    goto :goto_1

    :cond_1
    invoke-virtual {p1, p3}, Llyiahf/vczjk/ak1;->OooO0o0(Llyiahf/vczjk/ak1;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0(Llyiahf/vczjk/c62;Llyiahf/vczjk/c62;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g69;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget p1, p1, Llyiahf/vczjk/c62;->OooO0oO:I

    const/4 v0, 0x2

    if-lt p1, v0, :cond_0

    iget p1, p2, Llyiahf/vczjk/c62;->OooO0oO:I

    if-lt p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0

    :pswitch_0
    iget p1, p1, Llyiahf/vczjk/c62;->OooO0oO:I

    const/4 v0, 0x2

    if-lt p1, v0, :cond_1

    iget p1, p2, Llyiahf/vczjk/c62;->OooO0oO:I

    if-lt p1, v0, :cond_1

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO()C
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g69;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const/16 v0, 0x3d

    return v0

    :pswitch_0
    const/16 v0, 0x7e

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0Oo()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g69;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x2

    return v0

    :pswitch_0
    const/4 v0, 0x2

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o0()C
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g69;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const/16 v0, 0x3d

    return v0

    :pswitch_0
    const/16 v0, 0x7e

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
