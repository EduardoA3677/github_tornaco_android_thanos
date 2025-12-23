.class public final Llyiahf/vczjk/id2;
.super Llyiahf/vczjk/er2;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0OO:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/id2;->OooO0OO:I

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/er2;-><init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;Z)V
    .locals 0

    const/4 p3, 0x0

    iput p3, p0, Llyiahf/vczjk/id2;->OooO0OO:I

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/er2;-><init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V

    return-void
.end method


# virtual methods
.method public final OooO0O0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/id2;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    const/16 v0, 0xa

    return v0

    :pswitch_0
    const/16 v0, 0x9

    return v0

    :pswitch_1
    const/4 v0, 0x2

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
