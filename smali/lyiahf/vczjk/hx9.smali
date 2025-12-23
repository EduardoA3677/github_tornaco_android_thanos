.class public final synthetic Llyiahf/vczjk/hx9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo:Llyiahf/vczjk/nf5;

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:Llyiahf/vczjk/ix9;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;ILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;JLlyiahf/vczjk/nf5;Llyiahf/vczjk/ix9;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hx9;->OooOOO0:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/hx9;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/hx9;->OooOOOO:Llyiahf/vczjk/ow6;

    iput-object p4, p0, Llyiahf/vczjk/hx9;->OooOOOo:Llyiahf/vczjk/ow6;

    iput-wide p5, p0, Llyiahf/vczjk/hx9;->OooOOo0:J

    iput-object p7, p0, Llyiahf/vczjk/hx9;->OooOOo:Llyiahf/vczjk/nf5;

    iput-object p8, p0, Llyiahf/vczjk/hx9;->OooOOoo:Llyiahf/vczjk/ix9;

    iput p9, p0, Llyiahf/vczjk/hx9;->OooOo00:I

    iput p10, p0, Llyiahf/vczjk/hx9;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/hx9;->OooOOO0:Llyiahf/vczjk/ow6;

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v2, p0, Llyiahf/vczjk/hx9;->OooOOO:I

    sub-int v1, v2, v1

    div-int/lit8 v1, v1, 0x2

    const/4 v3, 0x0

    invoke-static {p1, v0, v3, v1}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget v1, Llyiahf/vczjk/up;->OooO0oO:F

    iget-object v4, p0, Llyiahf/vczjk/hx9;->OooOOo:Llyiahf/vczjk/nf5;

    invoke-interface {v4, v1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v1

    iget v0, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/hx9;->OooOOOo:Llyiahf/vczjk/ow6;

    iget v4, v1, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-object v5, p0, Llyiahf/vczjk/hx9;->OooOOoo:Llyiahf/vczjk/ix9;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v6, p0, Llyiahf/vczjk/hx9;->OooOOOO:Llyiahf/vczjk/ow6;

    iget v7, v6, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-wide v8, p0, Llyiahf/vczjk/hx9;->OooOOo0:J

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v10

    sget-object v11, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    sub-int/2addr v10, v7

    int-to-float v7, v10

    const/high16 v10, 0x40000000    # 2.0f

    div-float/2addr v7, v10

    sget-object v10, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    const/4 v10, 0x1

    int-to-float v10, v10

    const/high16 v11, -0x40800000    # -1.0f

    add-float/2addr v10, v11

    mul-float/2addr v10, v7

    invoke-static {v10}, Ljava/lang/Math;->round(F)I

    move-result v7

    if-ge v7, v0, :cond_0

    sub-int/2addr v0, v7

    :goto_0
    add-int/2addr v7, v0

    goto :goto_1

    :cond_0
    iget v0, v6, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v0, v7

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v10

    sub-int/2addr v10, v4

    if-le v0, v10, :cond_1

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    sub-int/2addr v0, v4

    iget v4, v6, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v4, v7

    sub-int/2addr v0, v4

    goto :goto_0

    :cond_1
    :goto_1
    sget-object v0, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    iget-object v4, v5, Llyiahf/vczjk/ix9;->OooO0O0:Llyiahf/vczjk/px;

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    iget v0, v6, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v0, v2, v0

    div-int/lit8 v3, v0, 0x2

    goto :goto_2

    :cond_2
    sget-object v0, Llyiahf/vczjk/tx;->OooO0Oo:Llyiahf/vczjk/wp3;

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_5

    iget v0, v5, Llyiahf/vczjk/ix9;->OooO0OO:I

    if-nez v0, :cond_3

    iget v0, v6, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v3, v2, v0

    goto :goto_2

    :cond_3
    iget v4, v6, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v5, p0, Llyiahf/vczjk/hx9;->OooOo00:I

    sub-int v5, v4, v5

    sub-int/2addr v0, v5

    add-int v5, v0, v4

    iget v10, p0, Llyiahf/vczjk/hx9;->OooOo0:I

    if-le v5, v10, :cond_4

    sub-int/2addr v5, v10

    sub-int/2addr v0, v5

    :cond_4
    sub-int v4, v2, v4

    invoke-static {v3, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    sub-int v3, v4, v0

    :cond_5
    :goto_2
    invoke-static {p1, v6, v7, v3}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    iget v3, v1, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v0, v3

    iget v3, v1, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int/2addr v2, v3

    div-int/lit8 v2, v2, 0x2

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
