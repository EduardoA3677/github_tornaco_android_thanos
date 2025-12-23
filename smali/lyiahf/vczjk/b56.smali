.class public final Llyiahf/vczjk/b56;
.super Llyiahf/vczjk/a56;
.source "SourceFile"


# virtual methods
.method public final performHandwritingGesture(Landroid/view/inputmethod/HandwritingGesture;Ljava/util/concurrent/Executor;Ljava/util/function/IntConsumer;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/rj7;->performHandwritingGesture(Landroid/view/inputmethod/HandwritingGesture;Ljava/util/concurrent/Executor;Ljava/util/function/IntConsumer;)V

    :cond_0
    return-void
.end method

.method public final previewHandwritingGesture(Landroid/view/inputmethod/PreviewableHandwritingGesture;Landroid/os/CancellationSignal;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/rj7;->previewHandwritingGesture(Landroid/view/inputmethod/PreviewableHandwritingGesture;Landroid/os/CancellationSignal;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
