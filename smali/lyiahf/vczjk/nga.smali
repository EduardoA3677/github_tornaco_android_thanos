.class public final Llyiahf/vczjk/nga;
.super Llyiahf/vczjk/nh;
.source "SourceFile"


# instance fields
.field public Oooo:Llyiahf/vczjk/oe3;

.field public final Oooo0o:Llyiahf/vczjk/fz5;

.field public final Oooo0o0:Landroid/view/View;

.field public Oooo0oO:Llyiahf/vczjk/s58;

.field public Oooo0oo:Llyiahf/vczjk/oe3;

.field public OoooO00:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/oe3;Llyiahf/vczjk/lg1;Llyiahf/vczjk/t58;ILlyiahf/vczjk/tg6;)V
    .locals 7

    invoke-interface {p2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    move-object v5, p2

    check-cast v5, Landroid/view/View;

    new-instance v4, Llyiahf/vczjk/fz5;

    invoke-direct {v4}, Llyiahf/vczjk/fz5;-><init>()V

    move-object v0, p0

    move-object v1, p1

    move-object v2, p3

    move v3, p5

    move-object v6, p6

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/nh;-><init>(Landroid/content/Context;Llyiahf/vczjk/lg1;ILlyiahf/vczjk/fz5;Landroid/view/View;Llyiahf/vczjk/tg6;)V

    iput-object v5, v0, Llyiahf/vczjk/nga;->Oooo0o0:Landroid/view/View;

    iput-object v4, v0, Llyiahf/vczjk/nga;->Oooo0o:Llyiahf/vczjk/fz5;

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    const/4 p2, 0x0

    if-eqz p4, :cond_0

    invoke-interface {p4, p1}, Llyiahf/vczjk/t58;->OooO0OO(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p3

    goto :goto_0

    :cond_0
    move-object p3, p2

    :goto_0
    instance-of p5, p3, Landroid/util/SparseArray;

    if-eqz p5, :cond_1

    move-object p2, p3

    check-cast p2, Landroid/util/SparseArray;

    :cond_1
    if-eqz p2, :cond_2

    invoke-virtual {v5, p2}, Landroid/view/View;->restoreHierarchyState(Landroid/util/SparseArray;)V

    :cond_2
    if-eqz p4, :cond_3

    new-instance p2, Llyiahf/vczjk/jga;

    invoke-direct {p2, p0}, Llyiahf/vczjk/jga;-><init>(Llyiahf/vczjk/nga;)V

    invoke-interface {p4, p1, p2}, Llyiahf/vczjk/t58;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/le3;)Llyiahf/vczjk/s58;

    move-result-object p1

    invoke-direct {p0, p1}, Llyiahf/vczjk/nga;->setSavableRegistryEntry(Llyiahf/vczjk/s58;)V

    :cond_3
    sget-object p1, Llyiahf/vczjk/o6;->OooOoO:Llyiahf/vczjk/o6;

    iput-object p1, v0, Llyiahf/vczjk/nga;->Oooo0oo:Llyiahf/vczjk/oe3;

    iput-object p1, v0, Llyiahf/vczjk/nga;->Oooo:Llyiahf/vczjk/oe3;

    iput-object p1, v0, Llyiahf/vczjk/nga;->OoooO00:Llyiahf/vczjk/oe3;

    return-void
.end method

.method public static final OooOOO(Llyiahf/vczjk/nga;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Llyiahf/vczjk/nga;->setSavableRegistryEntry(Llyiahf/vczjk/s58;)V

    return-void
.end method

.method private final setSavableRegistryEntry(Llyiahf/vczjk/s58;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nga;->Oooo0oO:Llyiahf/vczjk/s58;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/ed5;

    invoke-virtual {v0}, Llyiahf/vczjk/ed5;->Oooo()V

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/nga;->Oooo0oO:Llyiahf/vczjk/s58;

    return-void
.end method


# virtual methods
.method public final getDispatcher()Llyiahf/vczjk/fz5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nga;->Oooo0o:Llyiahf/vczjk/fz5;

    return-object v0
.end method

.method public final getReleaseBlock()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nga;->OoooO00:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final getResetBlock()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nga;->Oooo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public bridge synthetic getSubCompositionView()Landroidx/compose/ui/platform/AbstractComposeView;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final getUpdateBlock()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nga;->Oooo0oo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public getViewRoot()Landroid/view/View;
    .locals 0

    return-object p0
.end method

.method public final setReleaseBlock(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nga;->OoooO00:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/kga;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kga;-><init>(Llyiahf/vczjk/nga;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nh;->setRelease(Llyiahf/vczjk/le3;)V

    return-void
.end method

.method public final setResetBlock(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nga;->Oooo:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/lga;

    invoke-direct {p1, p0}, Llyiahf/vczjk/lga;-><init>(Llyiahf/vczjk/nga;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nh;->setReset(Llyiahf/vczjk/le3;)V

    return-void
.end method

.method public final setUpdateBlock(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nga;->Oooo0oo:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/mga;

    invoke-direct {p1, p0}, Llyiahf/vczjk/mga;-><init>(Llyiahf/vczjk/nga;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nh;->setUpdate(Llyiahf/vczjk/le3;)V

    return-void
.end method
