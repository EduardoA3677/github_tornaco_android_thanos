.class public final synthetic Llyiahf/vczjk/px4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/px4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/px4;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/px4;->OooOOOo:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/px4;->OooOOO:F

    iput-object p4, p0, Llyiahf/vczjk/px4;->OooOOo0:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/nf5;F)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/px4;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/px4;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/px4;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/px4;->OooOOo0:Ljava/lang/Object;

    iput p4, p0, Llyiahf/vczjk/px4;->OooOOO:F

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/px4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/px4;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ow6;

    const/4 v1, 0x0

    invoke-static {p1, v0, v1, v1}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget v0, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-object v2, p0, Llyiahf/vczjk/px4;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/nf5;

    iget v3, p0, Llyiahf/vczjk/px4;->OooOOO:F

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    add-int/2addr v2, v0

    iget-object v0, p0, Llyiahf/vczjk/px4;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ow6;

    invoke-static {p1, v0, v2, v1}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/zp4;

    const-string v0, "$this$LazyVerticalGrid"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/px4;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    new-instance v2, Llyiahf/vczjk/rx4;

    invoke-direct {v2, v0}, Llyiahf/vczjk/rx4;-><init>(Ljava/util/ArrayList;)V

    new-instance v3, Llyiahf/vczjk/sx4;

    iget v4, p0, Llyiahf/vczjk/px4;->OooOOO:F

    iget-object v5, p0, Llyiahf/vczjk/px4;->OooOOo0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/tv7;

    iget-object v6, p0, Llyiahf/vczjk/px4;->OooOOOo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/di6;

    invoke-direct {v3, v0, v6, v4, v5}, Llyiahf/vczjk/sx4;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;)V

    new-instance v0, Llyiahf/vczjk/a91;

    const v4, 0x29b3c0fe

    const/4 v5, 0x1

    invoke-direct {v0, v4, v3, v5}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const/4 v3, 0x0

    invoke-virtual {p1, v1, v3, v2, v0}, Llyiahf/vczjk/zp4;->OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
