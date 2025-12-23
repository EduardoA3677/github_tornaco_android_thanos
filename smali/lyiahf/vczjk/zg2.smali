.class public final Llyiahf/vczjk/zg2;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/ah2;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ah2;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/zg2;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/zg2;->OooO0O0:Llyiahf/vczjk/ah2;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/zg2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/zg2;->OooO0O0:Llyiahf/vczjk/ah2;

    invoke-static {p1}, Llyiahf/vczjk/ah2;->OooO00o(Llyiahf/vczjk/ah2;)V

    iget-object v0, p1, Llyiahf/vczjk/ah2;->OooOOoo:Ljava/util/ArrayList;

    if-eqz v0, :cond_0

    iget-boolean v1, p1, Llyiahf/vczjk/ah2;->OooOo00:Z

    if-nez v1, :cond_0

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fi;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fi;->OooO00o(Landroid/graphics/drawable/Drawable;)V

    goto :goto_0

    :cond_0
    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public onAnimationStart(Landroid/animation/Animator;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/zg2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationStart(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationStart(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/zg2;->OooO0O0:Llyiahf/vczjk/ah2;

    iget-object v0, p1, Llyiahf/vczjk/ah2;->OooOOoo:Ljava/util/ArrayList;

    if-eqz v0, :cond_0

    iget-boolean v1, p1, Llyiahf/vczjk/ah2;->OooOo00:Z

    if-nez v1, :cond_0

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fi;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/fi;->OooO0O0(Landroid/graphics/drawable/Drawable;)V

    goto :goto_0

    :cond_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
