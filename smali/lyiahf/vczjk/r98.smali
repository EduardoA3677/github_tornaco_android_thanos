.class public final Llyiahf/vczjk/r98;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $xOffset:I

.field final synthetic $yOffset:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r98;->$placeable:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/r98;->$xOffset:I

    iput p3, p0, Llyiahf/vczjk/r98;->$yOffset:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/r98;->$placeable:Llyiahf/vczjk/ow6;

    iget v1, p0, Llyiahf/vczjk/r98;->$xOffset:I

    iget v2, p0, Llyiahf/vczjk/r98;->$yOffset:I

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
