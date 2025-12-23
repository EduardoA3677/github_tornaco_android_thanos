.class public final Llyiahf/vczjk/yk8;
.super Llyiahf/vczjk/wk8;
.source "SourceFile"


# direct methods
.method public constructor <init>(Landroid/widget/FrameLayout;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/wk8;-><init>()V

    invoke-direct {p0, p1}, Llyiahf/vczjk/yk8;->OooO0Oo(Landroid/view/View;)V

    return-void
.end method

.method private OooO0Oo(Landroid/view/View;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/uv0;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/uv0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/widget/FrameLayout;)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/wk8;->OooO00o:Z

    xor-int/lit8 v0, v0, 0x1

    invoke-virtual {p1, v0}, Landroid/view/View;->setClipToOutline(Z)V

    iget-boolean v0, p0, Llyiahf/vczjk/wk8;->OooO00o:Z

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Landroid/view/View;->invalidate()V

    return-void

    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->invalidateOutline()V

    return-void
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/wk8;->OooO00o:Z

    return v0
.end method
