.class public final Llyiahf/vczjk/pna;
.super Landroid/view/WindowInsetsAnimation$Callback;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/i11;

.field public OooO0O0:Ljava/util/List;

.field public OooO0OO:Ljava/util/ArrayList;

.field public final OooO0Oo:Ljava/util/HashMap;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i11;)V
    .locals 1

    iget v0, p1, Llyiahf/vczjk/i11;->OooOOO0:I

    invoke-direct {p0, v0}, Landroid/view/WindowInsetsAnimation$Callback;-><init>(I)V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/pna;->OooO0Oo:Ljava/util/HashMap;

    iput-object p1, p0, Llyiahf/vczjk/pna;->OooO00o:Llyiahf/vczjk/i11;

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/view/WindowInsetsAnimation;)Llyiahf/vczjk/sna;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO0Oo:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/sna;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/sna;

    const/4 v1, 0x0

    const/4 v2, 0x0

    const-wide/16 v3, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/sna;-><init>(ILandroid/view/animation/Interpolator;J)V

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1e

    if-lt v1, v2, :cond_0

    new-instance v1, Llyiahf/vczjk/qna;

    invoke-direct {v1, p1}, Llyiahf/vczjk/qna;-><init>(Landroid/view/WindowInsetsAnimation;)V

    iput-object v1, v0, Llyiahf/vczjk/sna;->OooO00o:Llyiahf/vczjk/rna;

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/pna;->OooO0Oo:Ljava/util/HashMap;

    invoke-virtual {v1, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    return-object v0
.end method

.method public final onEnd(Landroid/view/WindowInsetsAnimation;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO00o:Llyiahf/vczjk/i11;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/pna;->OooO00o(Landroid/view/WindowInsetsAnimation;)Llyiahf/vczjk/sna;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/i11;->OooO0Oo(Llyiahf/vczjk/sna;)V

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO0Oo:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final onPrepare(Landroid/view/WindowInsetsAnimation;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO00o:Llyiahf/vczjk/i11;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/pna;->OooO00o(Landroid/view/WindowInsetsAnimation;)Llyiahf/vczjk/sna;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/i11;->OooO0o0(Llyiahf/vczjk/sna;)V

    return-void
.end method

.method public final onProgress(Landroid/view/WindowInsets;Ljava/util/List;)Landroid/view/WindowInsets;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO0OO:Ljava/util/ArrayList;

    if-nez v0, :cond_0

    new-instance v0, Ljava/util/ArrayList;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/pna;->OooO0OO:Ljava/util/ArrayList;

    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/pna;->OooO0O0:Ljava/util/List;

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    :goto_0
    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_1
    if-ltz v0, :cond_1

    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ona;->OooOO0(Ljava/lang/Object;)Landroid/view/WindowInsetsAnimation;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/pna;->OooO00o(Landroid/view/WindowInsetsAnimation;)Llyiahf/vczjk/sna;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/ona;->OooOo0o(Landroid/view/WindowInsetsAnimation;)F

    move-result v1

    iget-object v3, v2, Llyiahf/vczjk/sna;->OooO00o:Llyiahf/vczjk/rna;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/rna;->OooO0o0(F)V

    iget-object v1, p0, Llyiahf/vczjk/pna;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v0, v0, -0x1

    goto :goto_1

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/pna;->OooO00o:Llyiahf/vczjk/i11;

    const/4 v0, 0x0

    invoke-static {v0, p1}, Llyiahf/vczjk/ioa;->OooO0oo(Landroid/view/View;Landroid/view/WindowInsets;)Llyiahf/vczjk/ioa;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO0O0:Ljava/util/List;

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/i11;->OooO0o(Llyiahf/vczjk/ioa;Ljava/util/List;)Llyiahf/vczjk/ioa;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0oO()Landroid/view/WindowInsets;

    move-result-object p1

    return-object p1
.end method

.method public final onStart(Landroid/view/WindowInsetsAnimation;Landroid/view/WindowInsetsAnimation$Bounds;)Landroid/view/WindowInsetsAnimation$Bounds;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/pna;->OooO00o:Llyiahf/vczjk/i11;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/pna;->OooO00o(Landroid/view/WindowInsetsAnimation;)Llyiahf/vczjk/sna;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/bp8;

    invoke-direct {v1, p2}, Llyiahf/vczjk/bp8;-><init>(Landroid/view/WindowInsetsAnimation$Bounds;)V

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/i11;->OooO0oO(Llyiahf/vczjk/sna;Llyiahf/vczjk/bp8;)Llyiahf/vczjk/bp8;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/ona;->OooOOO0()V

    iget-object p2, p1, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/x04;

    invoke-virtual {p2}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p2

    iget-object p1, p1, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/x04;

    invoke-virtual {p1}, Llyiahf/vczjk/x04;->OooO0o0()Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/ona;->OooO0oo(Landroid/graphics/Insets;Landroid/graphics/Insets;)Landroid/view/WindowInsetsAnimation$Bounds;

    move-result-object p1

    return-object p1
.end method
