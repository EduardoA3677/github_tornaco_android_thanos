.class public final Llyiahf/vczjk/gia;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/ArrayList;

.field public OooO0O0:J

.field public OooO0OO:Landroid/view/animation/BaseInterpolator;

.field public OooO0Oo:Llyiahf/vczjk/tp6;

.field public final OooO0o:Llyiahf/vczjk/yw9;

.field public OooO0o0:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v0, -0x1

    iput-wide v0, p0, Llyiahf/vczjk/gia;->OooO0O0:J

    new-instance v0, Llyiahf/vczjk/yw9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/yw9;-><init>(Llyiahf/vczjk/gia;)V

    iput-object v0, p0, Llyiahf/vczjk/gia;->OooO0o:Llyiahf/vczjk/yw9;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/gia;->OooO00o:Ljava/util/ArrayList;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/gia;->OooO0o0:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gia;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fia;

    invoke-virtual {v1}, Llyiahf/vczjk/fia;->OooO0O0()V

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/gia;->OooO0o0:Z

    return-void
.end method

.method public final OooO0O0()V
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/gia;->OooO0o0:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gia;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fia;

    iget-wide v2, p0, Llyiahf/vczjk/gia;->OooO0O0:J

    const-wide/16 v4, 0x0

    cmp-long v4, v2, v4

    if-ltz v4, :cond_2

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/fia;->OooO0OO(J)V

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/gia;->OooO0OO:Landroid/view/animation/BaseInterpolator;

    if-eqz v2, :cond_3

    iget-object v3, v1, Llyiahf/vczjk/fia;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/view/View;

    if-eqz v3, :cond_3

    invoke-virtual {v3}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    move-result-object v3

    invoke-virtual {v3, v2}, Landroid/view/ViewPropertyAnimator;->setInterpolator(Landroid/animation/TimeInterpolator;)Landroid/view/ViewPropertyAnimator;

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/gia;->OooO0Oo:Llyiahf/vczjk/tp6;

    if-eqz v2, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/gia;->OooO0o:Llyiahf/vczjk/yw9;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fia;->OooO0Oo(Llyiahf/vczjk/hia;)V

    :cond_4
    iget-object v1, v1, Llyiahf/vczjk/fia;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Landroid/view/View;->animate()Landroid/view/ViewPropertyAnimator;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/ViewPropertyAnimator;->start()V

    goto :goto_0

    :cond_5
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/gia;->OooO0o0:Z

    return-void
.end method
