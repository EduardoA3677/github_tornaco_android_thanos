.class public final Llyiahf/vczjk/lt4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $index:I

.field final synthetic $itemProvider:Llyiahf/vczjk/nt4;

.field final synthetic $key:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILjava/lang/Object;Llyiahf/vczjk/nt4;)V
    .locals 0

    iput-object p3, p0, Llyiahf/vczjk/lt4;->$itemProvider:Llyiahf/vczjk/nt4;

    iput p1, p0, Llyiahf/vczjk/lt4;->$index:I

    iput-object p2, p0, Llyiahf/vczjk/lt4;->$key:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

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

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/lt4;->$itemProvider:Llyiahf/vczjk/nt4;

    iget v0, p0, Llyiahf/vczjk/lt4;->$index:I

    iget-object v1, p0, Llyiahf/vczjk/lt4;->$key:Ljava/lang/Object;

    invoke-interface {p2, v0, v1, p1}, Llyiahf/vczjk/nt4;->OooO0o0(ILjava/lang/Object;Llyiahf/vczjk/zf1;)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
