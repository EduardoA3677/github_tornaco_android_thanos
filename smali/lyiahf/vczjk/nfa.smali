.class public final Llyiahf/vczjk/nfa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnApplyWindowInsetsListener;


# instance fields
.field public OooO00o:Llyiahf/vczjk/ioa;

.field public final synthetic OooO0O0:Landroid/view/View;

.field public final synthetic OooO0OO:Llyiahf/vczjk/u96;


# direct methods
.method public constructor <init>(Landroid/view/View;Llyiahf/vczjk/u96;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nfa;->OooO0O0:Landroid/view/View;

    iput-object p2, p0, Llyiahf/vczjk/nfa;->OooO0OO:Llyiahf/vczjk/u96;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/nfa;->OooO00o:Llyiahf/vczjk/ioa;

    return-void
.end method


# virtual methods
.method public onApplyWindowInsets(Landroid/view/View;Landroid/view/WindowInsets;)Landroid/view/WindowInsets;
    .locals 5

    invoke-static {p1, p2}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object v0

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    iget-object v2, p0, Llyiahf/vczjk/nfa;->OooO0OO:Llyiahf/vczjk/u96;

    const/16 v3, 0x1e

    if-ge v1, v3, :cond_0

    iget-object v4, p0, Llyiahf/vczjk/nfa;->OooO0O0:Landroid/view/View;

    invoke-static {p2, v4}, Llyiahf/vczjk/ofa;->OooO00o(Landroid/view/WindowInsets;Landroid/view/View;)V

    iget-object p2, p0, Llyiahf/vczjk/nfa;->OooO00o:Llyiahf/vczjk/ioa;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/ioa;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {v2, p1, v0}, Llyiahf/vczjk/u96;->Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    return-object p1

    :cond_0
    iput-object v0, p0, Llyiahf/vczjk/nfa;->OooO00o:Llyiahf/vczjk/ioa;

    invoke-interface {v2, p1, v0}, Llyiahf/vczjk/u96;->Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object p2

    if-lt v1, v3, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    return-object p1

    :cond_1
    sget-object v0, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {p1}, Llyiahf/vczjk/mfa;->OooO0OO(Landroid/view/View;)V

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    return-object p1
.end method
