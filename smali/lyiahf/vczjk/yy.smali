.class public Llyiahf/vczjk/yy;
.super Llyiahf/vczjk/e5a;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0OO:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/yy;->OooO0OO:I

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/e5a;-><init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;)V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/yy;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/e5a;->OooO0O0:Llyiahf/vczjk/db0;

    if-ne v0, p1, :cond_0

    move-object v0, p0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/yy;

    iget-object v1, p0, Llyiahf/vczjk/e5a;->OooO00o:Llyiahf/vczjk/d4a;

    const/4 v2, 0x1

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/yy;-><init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;I)V

    :goto_0
    return-object v0

    :pswitch_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/yy;->OooO0oO(Llyiahf/vczjk/db0;)Llyiahf/vczjk/yy;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0OO()Llyiahf/vczjk/kc4;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yy;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/kc4;->OooOOO:Llyiahf/vczjk/kc4;

    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/kc4;->OooOOOO:Llyiahf/vczjk/kc4;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oO(Llyiahf/vczjk/db0;)Llyiahf/vczjk/yy;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e5a;->OooO0O0:Llyiahf/vczjk/db0;

    if-ne v0, p1, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/yy;

    iget-object v1, p0, Llyiahf/vczjk/e5a;->OooO00o:Llyiahf/vczjk/d4a;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/yy;-><init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;I)V

    return-object v0
.end method
