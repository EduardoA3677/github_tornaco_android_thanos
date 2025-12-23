.class public final Llyiahf/vczjk/hc1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cu8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cu8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/hc1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/hc1;->OooOOO:Llyiahf/vczjk/cu8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/hc1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object p2, p0, Llyiahf/vczjk/hc1;->OooOOO:Llyiahf/vczjk/cu8;

    const/4 v0, 0x6

    const/4 v1, 0x0

    invoke-static {p2, v1, v1, p1, v0}, Llyiahf/vczjk/br6;->OooOO0(Llyiahf/vczjk/cu8;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_3

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    iget-object p2, p0, Llyiahf/vczjk/hc1;->OooOOO:Llyiahf/vczjk/cu8;

    const/4 v0, 0x6

    const/4 v1, 0x0

    invoke-static {p2, v1, v1, p1, v0}, Llyiahf/vczjk/br6;->OooOO0(Llyiahf/vczjk/cu8;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
