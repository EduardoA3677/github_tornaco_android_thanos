.class public final Llyiahf/vczjk/xq4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $itemIndex:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/xq4;->$itemIndex:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/vq4;

    iget p1, p1, Llyiahf/vczjk/vq4;->OooO00o:I

    iget v0, p0, Llyiahf/vczjk/xq4;->$itemIndex:I

    sub-int/2addr p1, v0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method
