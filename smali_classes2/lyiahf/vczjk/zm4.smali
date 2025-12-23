.class public final Llyiahf/vczjk/zm4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/animation/Animator$AnimatorListener;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/tqa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tqa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zm4;->OooO00o:Llyiahf/vczjk/tqa;

    return-void
.end method


# virtual methods
.method public final onAnimationCancel(Landroid/animation/Animator;)V
    .locals 0

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/zm4;->OooO00o:Llyiahf/vczjk/tqa;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_0
    return-void
.end method

.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zm4;->OooO00o:Llyiahf/vczjk/tqa;

    iget-object v0, v0, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oo0ooO;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/oo0ooO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final onAnimationRepeat(Landroid/animation/Animator;)V
    .locals 0

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/zm4;->OooO00o:Llyiahf/vczjk/tqa;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_0
    return-void
.end method

.method public final onAnimationStart(Landroid/animation/Animator;)V
    .locals 0

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/zm4;->OooO00o:Llyiahf/vczjk/tqa;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_0
    return-void
.end method
