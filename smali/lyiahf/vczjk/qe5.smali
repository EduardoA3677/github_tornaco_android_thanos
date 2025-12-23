.class public final Llyiahf/vczjk/qe5;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Z

.field public final synthetic OooO0O0:I

.field public final synthetic OooO0OO:Llyiahf/vczjk/re5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/re5;ZI)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qe5;->OooO0OO:Llyiahf/vczjk/re5;

    iput-boolean p2, p0, Llyiahf/vczjk/qe5;->OooO00o:Z

    iput p3, p0, Llyiahf/vczjk/qe5;->OooO0O0:I

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method


# virtual methods
.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 3

    iget-object p1, p0, Llyiahf/vczjk/qe5;->OooO0OO:Llyiahf/vczjk/re5;

    iget-object v0, p1, Llyiahf/vczjk/md5;->OooO0O0:Landroid/view/View;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/view/View;->setTranslationX(F)V

    iget-boolean v0, p0, Llyiahf/vczjk/qe5;->OooO00o:Z

    iget v2, p0, Llyiahf/vczjk/qe5;->OooO0O0:I

    invoke-virtual {p1, v1, v2, v0}, Llyiahf/vczjk/re5;->OooO0Oo(FIZ)V

    return-void
.end method
