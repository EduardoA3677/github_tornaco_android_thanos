.class public final Llyiahf/vczjk/wh4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/xh4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xh4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/wh4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/wh4;->OooOOO:Llyiahf/vczjk/xh4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/wh4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/wh4;->OooOOO:Llyiahf/vczjk/xh4;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOO0o(Llyiahf/vczjk/vh4;Z)Llyiahf/vczjk/so0;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/wh4;->OooOOO:Llyiahf/vczjk/xh4;

    invoke-virtual {v0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/vh4;->OooOo00()Llyiahf/vczjk/ai4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ai4;->OooOo00()Llyiahf/vczjk/sa7;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-static {v0, v1}, Llyiahf/vczjk/dn8;->Oooo0oO(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;)Llyiahf/vczjk/va7;

    move-result-object v1

    :cond_0
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
