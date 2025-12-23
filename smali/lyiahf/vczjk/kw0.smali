.class public final synthetic Llyiahf/vczjk/kw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;IILlyiahf/vczjk/ow6;ILlyiahf/vczjk/ow6;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kw0;->OooOOO0:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/kw0;->OooOOO:I

    iput p3, p0, Llyiahf/vczjk/kw0;->OooOOOO:I

    iput-object p4, p0, Llyiahf/vczjk/kw0;->OooOOOo:Llyiahf/vczjk/ow6;

    iput p5, p0, Llyiahf/vczjk/kw0;->OooOOo0:I

    iput-object p6, p0, Llyiahf/vczjk/kw0;->OooOOo:Llyiahf/vczjk/ow6;

    iput p7, p0, Llyiahf/vczjk/kw0;->OooOOoo:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/nw6;

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/kw0;->OooOOO0:Llyiahf/vczjk/ow6;

    iget v2, p0, Llyiahf/vczjk/kw0;->OooOOOO:I

    const/4 v3, 0x0

    const/4 v4, 0x1

    const/high16 v5, 0x40000000    # 2.0f

    if-eqz v1, :cond_0

    iget v6, p0, Llyiahf/vczjk/kw0;->OooOOO:I

    sub-int v6, v2, v6

    int-to-float v6, v6

    div-float/2addr v6, v5

    int-to-float v7, v4

    add-float/2addr v7, v3

    mul-float/2addr v7, v6

    invoke-static {v7}, Ljava/lang/Math;->round(F)I

    move-result v6

    invoke-static {p1, v1, v0, v6}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/kw0;->OooOOOo:Llyiahf/vczjk/ow6;

    iget v6, p0, Llyiahf/vczjk/kw0;->OooOOo0:I

    invoke-static {p1, v1, v6, v0}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v0, p0, Llyiahf/vczjk/kw0;->OooOOo:Llyiahf/vczjk/ow6;

    if-eqz v0, :cond_1

    iget v1, v1, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v6, v1

    iget v1, p0, Llyiahf/vczjk/kw0;->OooOOoo:I

    sub-int/2addr v2, v1

    int-to-float v1, v2

    div-float/2addr v1, v5

    int-to-float v2, v4

    add-float/2addr v2, v3

    mul-float/2addr v2, v1

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-static {p1, v0, v6, v1}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
