.class public Llyiahf/vczjk/coa;
.super Llyiahf/vczjk/boa;
.source "SourceFile"


# instance fields
.field public OooOOOO:Llyiahf/vczjk/x04;

.field public OooOOOo:Llyiahf/vczjk/x04;

.field public OooOOo0:Llyiahf/vczjk/x04;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/boa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOOO:Llyiahf/vczjk/x04;

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOOo:Llyiahf/vczjk/x04;

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOo0:Llyiahf/vczjk/x04;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/coa;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/boa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/boa;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOOO:Llyiahf/vczjk/x04;

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOOo:Llyiahf/vczjk/x04;

    iput-object p1, p0, Llyiahf/vczjk/coa;->OooOOo0:Llyiahf/vczjk/x04;

    return-void
.end method


# virtual methods
.method public OooO()Llyiahf/vczjk/x04;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOOo:Llyiahf/vczjk/x04;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0}, Llyiahf/vczjk/una;->OooO0o(Landroid/view/WindowInsets;)Landroid/graphics/Insets;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/coa;->OooOOOo:Llyiahf/vczjk/x04;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOOo:Llyiahf/vczjk/x04;

    return-object v0
.end method

.method public OooOO0O()Llyiahf/vczjk/x04;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOOO:Llyiahf/vczjk/x04;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0}, Llyiahf/vczjk/una;->OooO0oo(Landroid/view/WindowInsets;)Landroid/graphics/Insets;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/coa;->OooOOOO:Llyiahf/vczjk/x04;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOOO:Llyiahf/vczjk/x04;

    return-object v0
.end method

.method public OooOOO(IIII)Llyiahf/vczjk/ioa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0, p1, p2, p3, p4}, Llyiahf/vczjk/una;->OooO0OO(Landroid/view/WindowInsets;IIII)Landroid/view/WindowInsets;

    move-result-object p1

    const/4 p2, 0x0

    invoke-static {p2, p1}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object p1

    return-object p1
.end method

.method public OooOOO0()Llyiahf/vczjk/x04;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOo0:Llyiahf/vczjk/x04;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {v0}, Llyiahf/vczjk/una;->OooO00o(Landroid/view/WindowInsets;)Landroid/graphics/Insets;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/coa;->OooOOo0:Llyiahf/vczjk/x04;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/coa;->OooOOo0:Llyiahf/vczjk/x04;

    return-object v0
.end method

.method public OooOo0(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method
