.class public final Llyiahf/vczjk/de;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $transformOriginState:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/de;->$transformOriginState:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/y14;

    check-cast p2, Llyiahf/vczjk/y14;

    iget-object v0, p0, Llyiahf/vczjk/de;->$transformOriginState:Llyiahf/vczjk/qs5;

    sget v1, Llyiahf/vczjk/th5;->OooO00o:F

    iget v1, p2, Llyiahf/vczjk/y14;->OooO00o:I

    iget v2, p1, Llyiahf/vczjk/y14;->OooO0OO:I

    const/high16 v3, 0x3f800000    # 1.0f

    const/4 v4, 0x0

    if-lt v1, v2, :cond_0

    :goto_0
    move v1, v4

    goto :goto_1

    :cond_0
    iget v1, p2, Llyiahf/vczjk/y14;->OooO0OO:I

    iget v2, p1, Llyiahf/vczjk/y14;->OooO00o:I

    if-gt v1, v2, :cond_1

    move v1, v3

    goto :goto_1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/y14;->OooO0Oo()I

    move-result v5

    if-nez v5, :cond_2

    goto :goto_0

    :cond_2
    iget v5, p2, Llyiahf/vczjk/y14;->OooO00o:I

    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    move-result v2

    iget v6, p1, Llyiahf/vczjk/y14;->OooO0OO:I

    invoke-static {v6, v1}, Ljava/lang/Math;->min(II)I

    move-result v1

    add-int/2addr v1, v2

    div-int/lit8 v1, v1, 0x2

    sub-int/2addr v1, v5

    int-to-float v1, v1

    invoke-virtual {p2}, Llyiahf/vczjk/y14;->OooO0Oo()I

    move-result v2

    int-to-float v2, v2

    div-float/2addr v1, v2

    :goto_1
    iget v2, p2, Llyiahf/vczjk/y14;->OooO0O0:I

    iget v5, p1, Llyiahf/vczjk/y14;->OooO0Oo:I

    if-lt v2, v5, :cond_3

    :goto_2
    move v3, v4

    goto :goto_3

    :cond_3
    iget v6, p2, Llyiahf/vczjk/y14;->OooO0Oo:I

    iget p1, p1, Llyiahf/vczjk/y14;->OooO0O0:I

    if-gt v6, p1, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/y14;->OooO0O0()I

    move-result v3

    if-nez v3, :cond_5

    goto :goto_2

    :cond_5
    invoke-static {p1, v2}, Ljava/lang/Math;->max(II)I

    move-result p1

    invoke-static {v5, v6}, Ljava/lang/Math;->min(II)I

    move-result v3

    add-int/2addr v3, p1

    div-int/lit8 v3, v3, 0x2

    sub-int/2addr v3, v2

    int-to-float p1, v3

    invoke-virtual {p2}, Llyiahf/vczjk/y14;->OooO0O0()I

    move-result p2

    int-to-float p2, p2

    div-float v3, p1, p2

    :goto_3
    invoke-static {v1, v3}, Llyiahf/vczjk/vl6;->OooO0OO(FF)J

    move-result-wide p1

    new-instance v1, Llyiahf/vczjk/ey9;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/ey9;-><init>(J)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
