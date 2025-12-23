.class public final Llyiahf/vczjk/tz4;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/uz4;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/uz4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tz4;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/tz4;->OooO0O0:Llyiahf/vczjk/uz4;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tz4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/tz4;->OooO0O0:Llyiahf/vczjk/uz4;

    invoke-virtual {p1}, Llyiahf/vczjk/uz4;->OooO0o0()V

    iget-object v0, p1, Llyiahf/vczjk/uz4;->OooOO0:Llyiahf/vczjk/p80;

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/o0O00o00;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/dx3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/p80;->OooO00o(Landroid/graphics/drawable/Drawable;)V

    :cond_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public onAnimationRepeat(Landroid/animation/Animator;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/tz4;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationRepeat(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationRepeat(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/tz4;->OooO0O0:Llyiahf/vczjk/uz4;

    iget v0, p1, Llyiahf/vczjk/uz4;->OooO0oO:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iget-object v2, p1, Llyiahf/vczjk/uz4;->OooO0o:Lcom/google/android/material/progressindicator/LinearProgressIndicatorSpec;

    iget-object v2, v2, Llyiahf/vczjk/q80;->OooO0o0:[I

    array-length v2, v2

    rem-int/2addr v0, v2

    iput v0, p1, Llyiahf/vczjk/uz4;->OooO0oO:I

    iput-boolean v1, p1, Llyiahf/vczjk/uz4;->OooO0oo:Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
