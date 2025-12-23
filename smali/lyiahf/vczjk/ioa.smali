.class public final Llyiahf/vczjk/ioa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/ioa;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/foa;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    sget-object v0, Llyiahf/vczjk/eoa;->OooOOoo:Llyiahf/vczjk/ioa;

    sput-object v0, Llyiahf/vczjk/ioa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-void

    :cond_0
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_1

    sget-object v0, Llyiahf/vczjk/doa;->OooOOo:Llyiahf/vczjk/ioa;

    sput-object v0, Llyiahf/vczjk/ioa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-void

    :cond_1
    sget-object v0, Llyiahf/vczjk/foa;->OooO0O0:Llyiahf/vczjk/ioa;

    sput-object v0, Llyiahf/vczjk/ioa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsets;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/eoa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/eoa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void

    :cond_0
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/doa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/doa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void

    :cond_1
    const/16 v1, 0x1d

    if-lt v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/coa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/coa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void

    :cond_2
    const/16 v1, 0x1c

    if-lt v0, v1, :cond_3

    new-instance v0, Llyiahf/vczjk/boa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/boa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void

    :cond_3
    new-instance v0, Llyiahf/vczjk/aoa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/aoa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_6

    iget-object p1, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    instance-of v1, p1, Llyiahf/vczjk/eoa;

    if-eqz v1, :cond_0

    new-instance v0, Llyiahf/vczjk/eoa;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/eoa;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/eoa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/eoa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_0
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_1

    instance-of v1, p1, Llyiahf/vczjk/doa;

    if-eqz v1, :cond_1

    new-instance v0, Llyiahf/vczjk/doa;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/doa;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/doa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/doa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_1
    const/16 v1, 0x1d

    if-lt v0, v1, :cond_2

    instance-of v1, p1, Llyiahf/vczjk/coa;

    if-eqz v1, :cond_2

    new-instance v0, Llyiahf/vczjk/coa;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/coa;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/coa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/coa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_2
    const/16 v1, 0x1c

    if-lt v0, v1, :cond_3

    instance-of v0, p1, Llyiahf/vczjk/boa;

    if-eqz v0, :cond_3

    new-instance v0, Llyiahf/vczjk/boa;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/boa;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/boa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/boa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_3
    instance-of v0, p1, Llyiahf/vczjk/aoa;

    if-eqz v0, :cond_4

    new-instance v0, Llyiahf/vczjk/aoa;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/aoa;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/aoa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/aoa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_4
    instance-of v0, p1, Llyiahf/vczjk/zna;

    if-eqz v0, :cond_5

    new-instance v0, Llyiahf/vczjk/zna;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/zna;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/zna;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/zna;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    goto :goto_0

    :cond_5
    new-instance v0, Llyiahf/vczjk/foa;

    invoke-direct {v0, p0}, Llyiahf/vczjk/foa;-><init>(Llyiahf/vczjk/ioa;)V

    iput-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    :goto_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/foa;->OooO0o0(Llyiahf/vczjk/ioa;)V

    return-void

    :cond_6
    new-instance p1, Llyiahf/vczjk/foa;

    invoke-direct {p1, p0}, Llyiahf/vczjk/foa;-><init>(Llyiahf/vczjk/ioa;)V

    iput-object p1, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    return-void
.end method

.method public static OooO0o0(Llyiahf/vczjk/x04;IIII)Llyiahf/vczjk/x04;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/x04;->OooO00o:I

    sub-int/2addr v0, p1

    const/4 v1, 0x0

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    iget v2, p0, Llyiahf/vczjk/x04;->OooO0O0:I

    sub-int/2addr v2, p2

    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    move-result v2

    iget v3, p0, Llyiahf/vczjk/x04;->OooO0OO:I

    sub-int/2addr v3, p3

    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    move-result v3

    iget v4, p0, Llyiahf/vczjk/x04;->OooO0Oo:I

    sub-int/2addr v4, p4

    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    move-result v1

    if-ne v0, p1, :cond_0

    if-ne v2, p2, :cond_0

    if-ne v3, p3, :cond_0

    if-ne v1, p4, :cond_0

    return-object p0

    :cond_0
    invoke-static {v0, v2, v3, v1}, Llyiahf/vczjk/x04;->OooO0OO(IIII)Llyiahf/vczjk/x04;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ioa;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ioa;-><init>(Landroid/view/WindowInsets;)V

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {p0}, Llyiahf/vczjk/pfa;->OooO00o(Landroid/view/View;)Llyiahf/vczjk/ioa;

    move-result-object p1

    iget-object v1, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/foa;->OooOo00(Llyiahf/vczjk/ioa;)V

    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/foa;->OooO0Oo(Landroid/view/View;)V

    invoke-virtual {p0}, Landroid/view/View;->getWindowSystemUiVisibility()I

    move-result p0

    invoke-virtual {v1, p0}, Llyiahf/vczjk/foa;->OooOo0O(I)V

    :cond_0
    return-object v0
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/x04;->OooO0Oo:I

    return v0
.end method

.method public final OooO0O0()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/x04;->OooO00o:I

    return v0
.end method

.method public final OooO0OO()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/x04;->OooO0OO:I

    return v0
.end method

.method public final OooO0Oo()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/x04;->OooO0O0:I

    return v0
.end method

.method public final OooO0o(IIII)Llyiahf/vczjk/ioa;
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/xna;

    invoke-direct {v0, p0}, Llyiahf/vczjk/xna;-><init>(Llyiahf/vczjk/ioa;)V

    goto :goto_0

    :cond_0
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/wna;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wna;-><init>(Llyiahf/vczjk/ioa;)V

    goto :goto_0

    :cond_1
    const/16 v1, 0x1d

    if-lt v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/vna;

    invoke-direct {v0, p0}, Llyiahf/vczjk/vna;-><init>(Llyiahf/vczjk/ioa;)V

    goto :goto_0

    :cond_2
    new-instance v0, Llyiahf/vczjk/tna;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tna;-><init>(Llyiahf/vczjk/ioa;)V

    :goto_0
    invoke-static {p1, p2, p3, p4}, Llyiahf/vczjk/x04;->OooO0OO(IIII)Llyiahf/vczjk/x04;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yna;->OooO0oO(Llyiahf/vczjk/x04;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yna;->OooO0O0()Llyiahf/vczjk/ioa;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oO()Landroid/view/WindowInsets;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    instance-of v1, v0, Llyiahf/vczjk/zna;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/zna;

    iget-object v0, v0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/ioa;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/ioa;

    iget-object p1, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-static {v0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/foa;->hashCode()I

    move-result v0

    return v0
.end method
