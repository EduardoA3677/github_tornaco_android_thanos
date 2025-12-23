.class public final Lcoil/compose/ContentPainterElement;
.super Llyiahf/vczjk/tl5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/tl5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0081\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Lcoil/compose/ContentPainterElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/cn1;",
        "coil-compose-base_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooOOO:Llyiahf/vczjk/o4;

.field public final OooOOO0:Llyiahf/vczjk/j00;

.field public final OooOOOO:Llyiahf/vczjk/en1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/o4;Llyiahf/vczjk/en1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    iput-object p2, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    iput-object p3, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/cn1;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    iput-object v1, v0, Llyiahf/vczjk/cn1;->OooOoOO:Llyiahf/vczjk/j00;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    iput-object v1, v0, Llyiahf/vczjk/cn1;->OooOoo0:Llyiahf/vczjk/o4;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    iput-object v1, v0, Llyiahf/vczjk/cn1;->OooOoo:Llyiahf/vczjk/en1;

    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, v0, Llyiahf/vczjk/cn1;->OooOooO:F

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 5

    check-cast p1, Llyiahf/vczjk/cn1;

    iget-object v0, p1, Llyiahf/vczjk/cn1;->OooOoOO:Llyiahf/vczjk/j00;

    invoke-virtual {v0}, Llyiahf/vczjk/j00;->OooO0oo()J

    move-result-wide v0

    iget-object v2, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    invoke-virtual {v2}, Llyiahf/vczjk/j00;->OooO0oo()J

    move-result-wide v3

    invoke-static {v0, v1, v3, v4}, Llyiahf/vczjk/tq8;->OooO00o(JJ)Z

    move-result v0

    iput-object v2, p1, Llyiahf/vczjk/cn1;->OooOoOO:Llyiahf/vczjk/j00;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    iput-object v1, p1, Llyiahf/vczjk/cn1;->OooOoo0:Llyiahf/vczjk/o4;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    iput-object v1, p1, Llyiahf/vczjk/cn1;->OooOoo:Llyiahf/vczjk/en1;

    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, p1, Llyiahf/vczjk/cn1;->OooOooO:F

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Lcoil/compose/ContentPainterElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Lcoil/compose/ContentPainterElement;

    iget-object v0, p1, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    iget-object v1, p1, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    iget-object v0, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    iget-object p1, p1, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_4

    goto :goto_0

    :cond_4
    const/high16 p1, 0x3f800000    # 1.0f

    invoke-static {p1, p1}, Ljava/lang/Float;->compare(FF)I

    move-result p1

    if-eqz p1, :cond_5

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_5
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-object v0, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v2

    mul-int/2addr v0, v1

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ContentPainterElement(painter="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO0:Llyiahf/vczjk/j00;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", alignment="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOO:Llyiahf/vczjk/o4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", contentScale="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lcoil/compose/ContentPainterElement;->OooOOOO:Llyiahf/vczjk/en1;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", alpha=1.0, colorFilter=null)"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
