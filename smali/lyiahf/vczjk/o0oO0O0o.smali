.class public final Llyiahf/vczjk/o0oO0O0o;
.super Llyiahf/vczjk/o0O00o00;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/rr7;

.field public static OooO0o0:Llyiahf/vczjk/o0oO0O0o;

.field public static final OooO0oO:Llyiahf/vczjk/rr7;


# instance fields
.field public OooO0OO:Llyiahf/vczjk/mm9;

.field public OooO0Oo:Llyiahf/vczjk/re8;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO:Llyiahf/vczjk/rr7;

    sput-object v0, Llyiahf/vczjk/o0oO0O0o;->OooO0o:Llyiahf/vczjk/rr7;

    sget-object v0, Llyiahf/vczjk/rr7;->OooOOO0:Llyiahf/vczjk/rr7;

    sput-object v0, Llyiahf/vczjk/o0oO0O0o;->OooO0oO:Llyiahf/vczjk/rr7;

    return-void
.end method


# virtual methods
.method public final OooO(I)[I
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/o0O00o00;->OooOOO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    if-gtz v0, :cond_0

    return-object v1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/o0O00o00;->OooOOO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    if-lt p1, v0, :cond_1

    return-object v1

    :cond_1
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0Oo:Llyiahf/vczjk/re8;

    if-eqz v0, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/re8;->OooO0o0()Llyiahf/vczjk/wj7;

    move-result-object v0

    iget v2, v0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v2, v0

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    if-lez p1, :cond_2

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    const-string v3, "layoutResult"

    if-eqz v2, :cond_9

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v2

    iget-object v4, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v4, :cond_8

    iget-object v4, v4, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/lq5;->OooO0o(I)F

    move-result v2

    int-to-float v0, v0

    add-float/2addr v2, v0

    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v0, :cond_7

    if-eqz v0, :cond_6

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget v4, v0, Llyiahf/vczjk/lq5;->OooO0o:I

    add-int/lit8 v4, v4, -0x1

    invoke-virtual {v0, v4}, Llyiahf/vczjk/lq5;->OooO0o(I)F

    move-result v0

    cmpg-float v0, v2, v0

    if-gez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/lq5;->OooO0o0(F)I

    move-result v0

    :goto_1
    add-int/lit8 v0, v0, -0x1

    goto :goto_2

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v0, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget v0, v0, Llyiahf/vczjk/lq5;->OooO0o:I

    goto :goto_1

    :goto_2
    sget-object v1, Llyiahf/vczjk/o0oO0O0o;->OooO0oO:Llyiahf/vczjk/rr7;

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/o0oO0O0o;->OooOoO(ILlyiahf/vczjk/rr7;)I

    move-result v0

    add-int/lit8 v0, v0, 0x1

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/o0O00o00;->OooOOO0(II)[I

    move-result-object p1

    return-object p1

    :cond_5
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_6
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_7
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_8
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_9
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_a
    :try_start_1
    const-string p1, "node"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    :catch_0
    return-object v1
.end method

.method public final OooOOo(I)[I
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/o0O00o00;->OooOOO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    if-gtz v0, :cond_0

    return-object v1

    :cond_0
    if-gtz p1, :cond_1

    return-object v1

    :cond_1
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0Oo:Llyiahf/vczjk/re8;

    if-eqz v0, :cond_8

    invoke-virtual {v0}, Llyiahf/vczjk/re8;->OooO0o0()Llyiahf/vczjk/wj7;

    move-result-object v0

    iget v2, v0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v2, v0

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {p0}, Llyiahf/vczjk/o0O00o00;->OooOOO()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    if-le v2, p1, :cond_2

    goto :goto_0

    :cond_2
    move p1, v2

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    const-string v3, "layoutResult"

    if-eqz v2, :cond_7

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v2

    iget-object v4, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v4, :cond_6

    iget-object v4, v4, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/lq5;->OooO0o(I)F

    move-result v4

    int-to-float v0, v0

    sub-float/2addr v4, v0

    const/4 v0, 0x0

    cmpl-float v0, v4, v0

    if-lez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v0, v4}, Llyiahf/vczjk/lq5;->OooO0o0(F)I

    move-result v0

    goto :goto_1

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_4
    const/4 v0, 0x0

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/o0O00o00;->OooOOO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-ne p1, v1, :cond_5

    if-ge v0, v2, :cond_5

    add-int/lit8 v0, v0, 0x1

    :cond_5
    sget-object v1, Llyiahf/vczjk/o0oO0O0o;->OooO0o:Llyiahf/vczjk/rr7;

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/o0oO0O0o;->OooOoO(ILlyiahf/vczjk/rr7;)I

    move-result v0

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/o0O00o00;->OooOOO0(II)[I

    move-result-object p1

    return-object p1

    :cond_6
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_7
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_8
    :try_start_1
    const-string p1, "node"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    :catch_0
    return-object v1
.end method

.method public final OooOoO(ILlyiahf/vczjk/rr7;)I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    const/4 v1, 0x0

    const-string v2, "layoutResult"

    if-eqz v0, :cond_4

    invoke-virtual {v0, p1}, Llyiahf/vczjk/mm9;->OooO0o(I)I

    move-result v0

    iget-object v3, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz v3, :cond_3

    invoke-virtual {v3, v0}, Llyiahf/vczjk/mm9;->OooO0oO(I)Llyiahf/vczjk/rr7;

    move-result-object v0

    if-eq p2, v0, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz p2, :cond_0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/mm9;->OooO0o(I)I

    move-result p1

    return p1

    :cond_0
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/o0oO0O0o;->OooO0OO:Llyiahf/vczjk/mm9;

    if-eqz p2, :cond_2

    iget-object p2, p2, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    const/4 v0, 0x0

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/lq5;->OooO0OO(IZ)I

    move-result p1

    add-int/lit8 p1, p1, -0x1

    return p1

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_3
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_4
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method
