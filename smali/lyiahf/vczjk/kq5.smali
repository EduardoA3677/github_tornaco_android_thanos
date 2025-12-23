.class public final Llyiahf/vczjk/kq5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $end:I

.field final synthetic $path:Llyiahf/vczjk/bq6;

.field final synthetic $start:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qe;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kq5;->$path:Llyiahf/vczjk/bq6;

    iput p2, p0, Llyiahf/vczjk/kq5;->$start:I

    iput p3, p0, Llyiahf/vczjk/kq5;->$end:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/bo6;

    iget-object v0, p0, Llyiahf/vczjk/kq5;->$path:Llyiahf/vczjk/bq6;

    iget v1, p0, Llyiahf/vczjk/kq5;->$start:I

    iget v2, p0, Llyiahf/vczjk/kq5;->$end:I

    iget-object v3, p1, Llyiahf/vczjk/bo6;->OooO00o:Llyiahf/vczjk/le;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/bo6;->OooO0Oo(I)I

    move-result v1

    invoke-virtual {p1, v2}, Llyiahf/vczjk/bo6;->OooO0Oo(I)I

    move-result v2

    iget-object v4, v3, Llyiahf/vczjk/le;->OooO0o0:Ljava/lang/CharSequence;

    if-ltz v1, :cond_0

    if-gt v1, v2, :cond_0

    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    move-result v5

    if-gt v2, v5, :cond_0

    goto :goto_0

    :cond_0
    const-string v5, "start("

    const-string v6, ") or end("

    const-string v7, ") is out of range [0.."

    invoke-static {v1, v2, v5, v6, v7}, Llyiahf/vczjk/ii5;->OooOOO0(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v5

    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    move-result v4

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v4, "], or start > end!"

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/qz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    new-instance v4, Landroid/graphics/Path;

    invoke-direct {v4}, Landroid/graphics/Path;-><init>()V

    iget-object v3, v3, Llyiahf/vczjk/le;->OooO0Oo:Llyiahf/vczjk/km9;

    iget-object v5, v3, Llyiahf/vczjk/km9;->OooO0o:Landroid/text/Layout;

    invoke-virtual {v5, v1, v2, v4}, Landroid/text/Layout;->getSelectionPath(IILandroid/graphics/Path;)V

    const/4 v1, 0x0

    iget v2, v3, Llyiahf/vczjk/km9;->OooO0oo:I

    if-eqz v2, :cond_1

    invoke-virtual {v4}, Landroid/graphics/Path;->isEmpty()Z

    move-result v3

    if-nez v3, :cond_1

    int-to-float v2, v2

    invoke-virtual {v4, v1, v2}, Landroid/graphics/Path;->offset(FF)V

    :cond_1
    new-instance v2, Llyiahf/vczjk/qe;

    invoke-direct {v2, v4}, Llyiahf/vczjk/qe;-><init>(Landroid/graphics/Path;)V

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v3, v1

    iget p1, p1, Llyiahf/vczjk/bo6;->OooO0o:F

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v5, p1

    const/16 p1, 0x20

    shl-long/2addr v3, p1

    const-wide v7, 0xffffffffL

    and-long/2addr v5, v7

    or-long/2addr v3, v5

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/qe;->OooOO0o(J)V

    invoke-static {v0, v2}, Llyiahf/vczjk/bq6;->OooO0OO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/qe;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
