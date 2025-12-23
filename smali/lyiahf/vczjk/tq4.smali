.class public final Llyiahf/vczjk/tq4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/qr5;

.field public final OooO0OO:Llyiahf/vczjk/qr5;

.field public OooO0Oo:Z

.field public final OooO0o:Llyiahf/vczjk/wt4;

.field public OooO0o0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(III)V
    .locals 1

    iput p3, p0, Llyiahf/vczjk/tq4;->OooO00o:I

    packed-switch p3, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    new-instance p2, Llyiahf/vczjk/wt4;

    const/16 p3, 0x5a

    const/16 v0, 0xc8

    invoke-direct {p2, p1, p3, v0}, Llyiahf/vczjk/wt4;-><init>(III)V

    iput-object p2, p0, Llyiahf/vczjk/tq4;->OooO0o:Llyiahf/vczjk/wt4;

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    new-instance p2, Llyiahf/vczjk/wt4;

    const/16 p3, 0x1e

    const/16 v0, 0x64

    invoke-direct {p2, p1, p3, v0}, Llyiahf/vczjk/wt4;-><init>(III)V

    iput-object p2, p0, Llyiahf/vczjk/tq4;->OooO0o:Llyiahf/vczjk/wt4;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tq4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tq4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(II)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/tq4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    int-to-float v0, p1

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-ltz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Index should be non-negative ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0o:Llyiahf/vczjk/wt4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wt4;->OooO00o(I)V

    iget-object p1, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    return-void

    :pswitch_0
    int-to-float v0, p1

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    if-ltz v0, :cond_1

    goto :goto_1

    :cond_1
    const-string v0, "Index should be non-negative"

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-object v0, p0, Llyiahf/vczjk/tq4;->OooO0o:Llyiahf/vczjk/wt4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wt4;->OooO00o(I)V

    iget-object p1, p0, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
