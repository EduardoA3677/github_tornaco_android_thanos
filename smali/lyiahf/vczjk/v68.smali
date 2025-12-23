.class public final Llyiahf/vczjk/v68;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:Llyiahf/vczjk/ys5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/ys5;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/v68;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/v68;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/v68;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p4, p0, Llyiahf/vczjk/v68;->OooOOOo:Llyiahf/vczjk/a91;

    iput-object p5, p0, Llyiahf/vczjk/v68;->OooOOo0:Llyiahf/vczjk/a91;

    iput-object p6, p0, Llyiahf/vczjk/v68;->OooOOo:Llyiahf/vczjk/ys5;

    iput-object p7, p0, Llyiahf/vczjk/v68;->OooOOoo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

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

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/v68;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v5, p0, Llyiahf/vczjk/v68;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v6, p0, Llyiahf/vczjk/v68;->OooOOo:Llyiahf/vczjk/ys5;

    iget v1, p0, Llyiahf/vczjk/v68;->OooOOO0:I

    iget-object v2, p0, Llyiahf/vczjk/v68;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v4, p0, Llyiahf/vczjk/v68;->OooOOOo:Llyiahf/vczjk/a91;

    iget-object v7, p0, Llyiahf/vczjk/v68;->OooOOoo:Llyiahf/vczjk/a91;

    const/4 v9, 0x0

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/j78;->OooO0O0(ILlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/kna;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
