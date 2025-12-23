.class public final Llyiahf/vczjk/oz0;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/pz0;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/pz0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/oz0;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/oz0;->OooO0O0:Llyiahf/vczjk/pz0;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/oz0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/oz0;->OooO0O0:Llyiahf/vczjk/pz0;

    iget-object p1, p1, Llyiahf/vczjk/on2;->OooO0O0:Llyiahf/vczjk/nn2;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/nn2;->OooO0oo(Z)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public onAnimationStart(Landroid/animation/Animator;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/oz0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationStart(Landroid/animation/Animator;)V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/oz0;->OooO0O0:Llyiahf/vczjk/pz0;

    iget-object p1, p1, Llyiahf/vczjk/on2;->OooO0O0:Llyiahf/vczjk/nn2;

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/nn2;->OooO0oo(Z)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
