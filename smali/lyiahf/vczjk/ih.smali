.class public final Llyiahf/vczjk/ih;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layoutNode:Llyiahf/vczjk/ro4;

.field final synthetic $this_run:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iput-object p2, p0, Llyiahf/vczjk/ih;->$layoutNode:Llyiahf/vczjk/ro4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/xn4;

    iget-object v0, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iget-object v1, p0, Llyiahf/vczjk/ih;->$layoutNode:Llyiahf/vczjk/ro4;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOO(Landroid/view/View;Llyiahf/vczjk/ro4;)V

    iget-object v0, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iget-object v1, v0, Llyiahf/vczjk/nh;->OooOOOO:Llyiahf/vczjk/tg6;

    check-cast v1, Llyiahf/vczjk/xa;

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/xa;->Oooo0O0:Z

    iget-object v1, v0, Llyiahf/vczjk/nh;->OooOoO:[I

    const/4 v3, 0x0

    aget v4, v1, v3

    aget v1, v1, v2

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object v0

    iget-object v5, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iget-object v5, v5, Llyiahf/vczjk/nh;->OooOoO:[I

    invoke-virtual {v0, v5}, Landroid/view/View;->getLocationOnScreen([I)V

    iget-object v0, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iget-wide v5, v0, Llyiahf/vczjk/nh;->OooOoOO:J

    invoke-interface {p1}, Llyiahf/vczjk/xn4;->OooOo00()J

    move-result-wide v7

    iput-wide v7, v0, Llyiahf/vczjk/nh;->OooOoOO:J

    iget-object p1, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    iget-object v0, p1, Llyiahf/vczjk/nh;->OooOoo0:Llyiahf/vczjk/ioa;

    if-eqz v0, :cond_1

    iget-object v7, p1, Llyiahf/vczjk/nh;->OooOoO:[I

    aget v3, v7, v3

    if-ne v4, v3, :cond_0

    aget v2, v7, v2

    if-ne v1, v2, :cond_0

    iget-wide v1, p1, Llyiahf/vczjk/nh;->OooOoOO:J

    invoke-static {v5, v6, v1, v2}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result p1

    if-nez p1, :cond_1

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/nh;->OooOOO0(Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ih;->$this_run:Llyiahf/vczjk/nh;

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/view/View;->dispatchApplyWindowInsets(Landroid/view/WindowInsets;)Landroid/view/WindowInsets;

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
