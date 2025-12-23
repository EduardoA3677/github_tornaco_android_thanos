.class public final Llyiahf/vczjk/vb;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $owner:Llyiahf/vczjk/xa;

.field final synthetic $uriHandler:Llyiahf/vczjk/xg;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/xg;Llyiahf/vczjk/ze3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vb;->$owner:Llyiahf/vczjk/xa;

    iput-object p2, p0, Llyiahf/vczjk/vb;->$uriHandler:Llyiahf/vczjk/xg;

    iput-object p3, p0, Llyiahf/vczjk/vb;->$content:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eq v0, v1, :cond_0

    move v0, v3

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    and-int/2addr p2, v3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/vb;->$owner:Llyiahf/vczjk/xa;

    iget-object v0, p0, Llyiahf/vczjk/vb;->$uriHandler:Llyiahf/vczjk/xg;

    iget-object v1, p0, Llyiahf/vczjk/vb;->$content:Llyiahf/vczjk/ze3;

    invoke-static {p2, v0, v1, p1, v2}, Llyiahf/vczjk/ch1;->OooO00o(Llyiahf/vczjk/tg6;Llyiahf/vczjk/raa;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
