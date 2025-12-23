.class public Llyiahf/vczjk/doa;
.super Llyiahf/vczjk/coa;
.source "SourceFile"


# static fields
.field public static final OooOOo:Llyiahf/vczjk/ioa;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    invoke-static {}, Llyiahf/vczjk/ona;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object v0

    const/4 v1, 0x0

    invoke-static {v1, v0}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/doa;->OooOOo:Llyiahf/vczjk/ioa;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/coa;-><init>(Llyiahf/vczjk/ioa;Landroid/view/WindowInsets;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/doa;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/coa;-><init>(Llyiahf/vczjk/ioa;Llyiahf/vczjk/coa;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public OooO0oO(I)Llyiahf/vczjk/x04;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {p1}, Llyiahf/vczjk/goa;->OooO00o(I)I

    move-result p1

    invoke-static {v0, p1}, Llyiahf/vczjk/ona;->OooO0Oo(Landroid/view/WindowInsets;I)Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object p1

    return-object p1
.end method

.method public OooO0oo(I)Llyiahf/vczjk/x04;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {p1}, Llyiahf/vczjk/goa;->OooO00o(I)I

    move-result p1

    invoke-static {v0, p1}, Llyiahf/vczjk/ona;->OooOo0(Landroid/view/WindowInsets;I)Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object p1

    return-object p1
.end method

.method public OooOOo0(I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zna;->OooO0OO:Landroid/view/WindowInsets;

    invoke-static {p1}, Llyiahf/vczjk/goa;->OooO00o(I)I

    move-result p1

    invoke-static {v0, p1}, Llyiahf/vczjk/ona;->OooOOo(Landroid/view/WindowInsets;I)Z

    move-result p1

    return p1
.end method
