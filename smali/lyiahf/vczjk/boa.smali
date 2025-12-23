.class public Llyiahf/vczjk/boa;
.super Llyiahf/vczjk/aoa;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/aoa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/boa;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/aoa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/aoa;)V

    return-void
.end method


# virtual methods
.method public OooO00o()Llyiahf/vczjk/ioa;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0}, Llyiahf/vczjk/md9;->OooO0o0(Landroid/view/WindowInsets;)Landroid/view/WindowInsets;

    move-result-object v0

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object v0

    return-object v0
.end method

.method public OooO0o()Llyiahf/vczjk/lc2;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0}, Llyiahf/vczjk/md9;->OooO0Oo(Landroid/view/WindowInsets;)Landroid/view/DisplayCutout;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/lc2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/lc2;-><init>(Landroid/view/DisplayCutout;)V

    return-object v1
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/boa;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/boa;

    iget-object v1, p1, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    iget-object v3, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v3, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/zna;->OooO0oO:Llyiahf/vczjk/x04;

    iget-object v3, p1, Llyiahf/vczjk/zna;->OooO0oO:Llyiahf/vczjk/x04;

    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    iget v1, p0, Llyiahf/vczjk/zna;->OooO0oo:I

    iget p1, p1, Llyiahf/vczjk/zna;->OooO0oo:I

    invoke-static {v1, p1}, Llyiahf/vczjk/zna;->OooOoo(II)Z

    move-result p1

    if-eqz p1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-virtual {v0}, Landroid/view/WindowInsets;->hashCode()I

    move-result v0

    return v0
.end method
