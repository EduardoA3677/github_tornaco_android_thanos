.class public final Llyiahf/vczjk/dz8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/di6;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/di6;Llyiahf/vczjk/a91;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/dz8;->OooOOO0:I

    iput-wide p1, p0, Llyiahf/vczjk/dz8;->OooOOO:J

    iput-object p3, p0, Llyiahf/vczjk/dz8;->OooOOOO:Llyiahf/vczjk/di6;

    iput-object p4, p0, Llyiahf/vczjk/dz8;->OooOOOo:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/dz8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    sget-object p1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n6a;

    iget-object v3, p1, Llyiahf/vczjk/n6a;->OooOOO0:Llyiahf/vczjk/rn9;

    new-instance p1, Llyiahf/vczjk/cz8;

    iget-object p2, p0, Llyiahf/vczjk/dz8;->OooOOOo:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/dz8;->OooOOOO:Llyiahf/vczjk/di6;

    const/4 v1, 0x1

    invoke-direct {p1, v0, p2, v1}, Llyiahf/vczjk/cz8;-><init>(Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;I)V

    const p2, 0x728ef7d8

    invoke-static {p2, p1, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v6, 0x180

    iget-wide v1, p0, Llyiahf/vczjk/dz8;->OooOOO:J

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_2

    move v0, v2

    goto :goto_2

    :cond_2
    const/4 v0, 0x0

    :goto_2
    and-int/2addr p2, v2

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n6a;

    iget-object v3, p1, Llyiahf/vczjk/n6a;->OooOOO0:Llyiahf/vczjk/rn9;

    new-instance p1, Llyiahf/vczjk/cz8;

    iget-object p2, p0, Llyiahf/vczjk/dz8;->OooOOOo:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/dz8;->OooOOOO:Llyiahf/vczjk/di6;

    const/4 v1, 0x0

    invoke-direct {p1, v0, p2, v1}, Llyiahf/vczjk/cz8;-><init>(Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;I)V

    const p2, -0x2e12cefa

    invoke-static {p2, p1, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v6, 0x180

    iget-wide v1, p0, Llyiahf/vczjk/dz8;->OooOOO:J

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_3

    :cond_3
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
