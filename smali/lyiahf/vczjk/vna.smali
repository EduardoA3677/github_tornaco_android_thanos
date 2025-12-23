.class public Llyiahf/vczjk/vna;
.super Llyiahf/vczjk/yna;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroid/view/WindowInsets$Builder;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/yna;-><init>()V

    invoke-static {}, Llyiahf/vczjk/hp7;->OooOO0O()Landroid/view/WindowInsets$Builder;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/yna;-><init>(Llyiahf/vczjk/ioa;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/una;->OooO0O0(Landroid/view/WindowInsets;)Landroid/view/WindowInsets$Builder;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/hp7;->OooOO0O()Landroid/view/WindowInsets$Builder;

    move-result-object p1

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    return-void
.end method


# virtual methods
.method public OooO0O0()Llyiahf/vczjk/ioa;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/yna;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-static {v0}, Llyiahf/vczjk/hp7;->OooOO0o(Landroid/view/WindowInsets$Builder;)Landroid/view/WindowInsets;

    move-result-object v0

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/yna;->OooO0O0:[Llyiahf/vczjk/x04;

    iget-object v2, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/foa;->OooOOo([Llyiahf/vczjk/x04;)V

    return-object v0
.end method

.method public OooO0Oo(Llyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/una;->OooO(Landroid/view/WindowInsets$Builder;Landroid/graphics/Insets;)V

    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/una;->OooO0oO(Landroid/view/WindowInsets$Builder;Landroid/graphics/Insets;)V

    return-void
.end method

.method public OooO0o0(Llyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/una;->OooO0o0(Landroid/view/WindowInsets$Builder;Landroid/graphics/Insets;)V

    return-void
.end method

.method public OooO0oO(Llyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/hp7;->OooOo(Landroid/view/WindowInsets$Builder;Landroid/graphics/Insets;)V

    return-void
.end method

.method public OooO0oo(Llyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/una;->OooOO0(Landroid/view/WindowInsets$Builder;Landroid/graphics/Insets;)V

    return-void
.end method
