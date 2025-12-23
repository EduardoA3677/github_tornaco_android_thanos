.class public Llyiahf/vczjk/wna;
.super Llyiahf/vczjk/vna;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/vna;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/vna;-><init>(Llyiahf/vczjk/ioa;)V

    return-void
.end method


# virtual methods
.method public OooO0OO(ILlyiahf/vczjk/x04;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vna;->OooO0OO:Landroid/view/WindowInsets$Builder;

    invoke-static {p1}, Llyiahf/vczjk/goa;->OooO00o(I)I

    move-result p1

    invoke-virtual {p2}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p2

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/ona;->OooOOOO(Landroid/view/WindowInsets$Builder;ILandroid/graphics/Insets;)V

    return-void
.end method
