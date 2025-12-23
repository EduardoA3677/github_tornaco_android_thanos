.class public final Llyiahf/vczjk/f83;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u83;
.implements Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;


# instance fields
.field public OooOoOO:Landroid/view/View;

.field public final OooOoo:Llyiahf/vczjk/d83;

.field public OooOoo0:Landroid/view/ViewTreeObserver;

.field public final OooOooO:Llyiahf/vczjk/e83;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    new-instance v0, Llyiahf/vczjk/d83;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d83;-><init>(Llyiahf/vczjk/f83;)V

    iput-object v0, p0, Llyiahf/vczjk/f83;->OooOoo:Llyiahf/vczjk/d83;

    new-instance v0, Llyiahf/vczjk/e83;

    invoke-direct {v0, p0}, Llyiahf/vczjk/e83;-><init>(Llyiahf/vczjk/f83;)V

    iput-object v0, p0, Llyiahf/vczjk/f83;->OooOooO:Llyiahf/vczjk/e83;

    return-void
.end method


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/s83;)V
    .locals 1

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Llyiahf/vczjk/s83;->OooO0Oo(Z)V

    iget-object v0, p0, Llyiahf/vczjk/f83;->OooOoo:Llyiahf/vczjk/d83;

    invoke-interface {p1, v0}, Llyiahf/vczjk/s83;->OooO0O0(Llyiahf/vczjk/d83;)V

    iget-object v0, p0, Llyiahf/vczjk/f83;->OooOooO:Llyiahf/vczjk/e83;

    invoke-interface {p1, v0}, Llyiahf/vczjk/s83;->OooO0OO(Llyiahf/vczjk/e83;)V

    return-void
.end method

.method public final o00000OO()Llyiahf/vczjk/d93;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "visitLocalDescendants called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget v1, v0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v1, v1, 0x400

    if-eqz v1, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-eqz v0, :cond_a

    iget v3, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v3, v3, 0x400

    if-eqz v3, :cond_9

    const/4 v3, 0x0

    move-object v4, v0

    move-object v5, v3

    :goto_1
    if-eqz v4, :cond_9

    instance-of v6, v4, Llyiahf/vczjk/d93;

    const/4 v7, 0x1

    if-eqz v6, :cond_2

    check-cast v4, Llyiahf/vczjk/d93;

    if-eqz v2, :cond_1

    return-object v4

    :cond_1
    move v2, v7

    goto :goto_4

    :cond_2
    iget v6, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v6, v6, 0x400

    if-eqz v6, :cond_8

    instance-of v6, v4, Llyiahf/vczjk/m52;

    if-eqz v6, :cond_8

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/m52;

    iget-object v6, v6, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v8, v1

    :goto_2
    if-eqz v6, :cond_7

    iget v9, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v9, v9, 0x400

    if-eqz v9, :cond_6

    add-int/lit8 v8, v8, 0x1

    if-ne v8, v7, :cond_3

    move-object v4, v6

    goto :goto_3

    :cond_3
    if-nez v5, :cond_4

    new-instance v5, Llyiahf/vczjk/ws5;

    const/16 v9, 0x10

    new-array v9, v9, [Llyiahf/vczjk/jl5;

    invoke-direct {v5, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_4
    if-eqz v4, :cond_5

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v3

    :cond_5
    invoke-virtual {v5, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_6
    :goto_3
    iget-object v6, v6, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_7
    if-ne v8, v7, :cond_8

    goto :goto_1

    :cond_8
    :goto_4
    invoke-static {v5}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_1

    :cond_9
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Could not find focus target of embedded view wrapper"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o000OOo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f83;->OooOoo0:Landroid/view/ViewTreeObserver;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/f83;->OooOoo0:Landroid/view/ViewTreeObserver;

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v1

    invoke-virtual {v1, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    iput-object v0, p0, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    return-void
.end method

.method public final o0O0O00()V
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/f83;->OooOoo0:Landroid/view/ViewTreeObserver;

    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->addOnGlobalFocusChangeListener(Landroid/view/ViewTreeObserver$OnGlobalFocusChangeListener;)V

    return-void
.end method

.method public final onGlobalFocusChanged(Landroid/view/View;Landroid/view/View;)V
    .locals 6

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-nez v0, :cond_0

    goto/16 :goto_2

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/c6a;->OooOoO0(Llyiahf/vczjk/jl5;)Landroid/view/View;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v2

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz p1, :cond_1

    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_1

    invoke-static {v0, p1}, Llyiahf/vczjk/c6a;->OooOo0o(Landroid/view/View;Landroid/view/View;)Z

    move-result p1

    if-eqz p1, :cond_1

    move p1, v3

    goto :goto_0

    :cond_1
    move p1, v4

    :goto_0
    if-eqz p2, :cond_2

    invoke-virtual {p2, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-static {v0, p2}, Llyiahf/vczjk/c6a;->OooOo0o(Landroid/view/View;Landroid/view/View;)Z

    move-result v0

    if-eqz v0, :cond_2

    move v0, v3

    goto :goto_1

    :cond_2
    move v0, v4

    :goto_1
    if-eqz p1, :cond_3

    if-eqz v0, :cond_3

    iput-object p2, p0, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    return-void

    :cond_3
    if-eqz v0, :cond_5

    iput-object p2, p0, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    invoke-virtual {p0}, Llyiahf/vczjk/f83;->o00000OO()Llyiahf/vczjk/d93;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    if-eqz p2, :cond_6

    if-eq p2, v3, :cond_6

    const/4 v0, 0x2

    if-eq p2, v0, :cond_6

    const/4 v0, 0x3

    if-ne p2, v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/bua;->Oooo0o0(Llyiahf/vczjk/d93;)Z

    return-void

    :cond_4
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_5
    const/4 p2, 0x0

    if-eqz p1, :cond_7

    iput-object p2, p0, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    invoke-virtual {p0}, Llyiahf/vczjk/f83;->o00000OO()Llyiahf/vczjk/d93;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result p1

    if-eqz p1, :cond_6

    const/16 p1, 0x8

    check-cast v1, Llyiahf/vczjk/r83;

    invoke-virtual {v1, p1, v4, v4}, Llyiahf/vczjk/r83;->OooO0O0(IZZ)Z

    :cond_6
    :goto_2
    return-void

    :cond_7
    iput-object p2, p0, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    return-void
.end method
