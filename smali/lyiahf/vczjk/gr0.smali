.class public final Llyiahf/vczjk/gr0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/view/View;Llyiahf/vczjk/sna;Llyiahf/vczjk/bp8;Landroid/animation/ValueAnimator;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/gr0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gr0;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gr0;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gr0;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/gr0;->OooOOo0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tg7;Llyiahf/vczjk/hr0;Llyiahf/vczjk/dh5;Llyiahf/vczjk/sg5;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/gr0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gr0;->OooOOo0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/gr0;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gr0;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/gr0;->OooOOOo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/gr0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/gr0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sna;

    iget-object v1, p0, Llyiahf/vczjk/gr0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/bp8;

    iget-object v2, p0, Llyiahf/vczjk/gr0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Landroid/view/View;

    invoke-static {v2, v0, v1}, Llyiahf/vczjk/nna;->OooO(Landroid/view/View;Llyiahf/vczjk/sna;Llyiahf/vczjk/bp8;)V

    iget-object v0, p0, Llyiahf/vczjk/gr0;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Landroid/animation/ValueAnimator;

    invoke-virtual {v0}, Landroid/animation/ValueAnimator;->start()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/gr0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hr0;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/gr0;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tg7;

    iget-object v2, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ir0;

    const/4 v3, 0x1

    iput-boolean v3, v2, Llyiahf/vczjk/ir0;->Oooo0o:Z

    iget-object v0, v0, Llyiahf/vczjk/hr0;->OooO0O0:Llyiahf/vczjk/sg5;

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/sg5;->OooO0OO(Z)V

    iget-object v0, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ir0;

    iput-boolean v2, v0, Llyiahf/vczjk/ir0;->Oooo0o:Z

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gr0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dh5;

    invoke-virtual {v0}, Llyiahf/vczjk/dh5;->isEnabled()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/dh5;->hasSubMenu()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/gr0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sg5;

    const/4 v2, 0x4

    const/4 v3, 0x0

    invoke-virtual {v1, v0, v3, v2}, Llyiahf/vczjk/sg5;->OooOOo0(Landroid/view/MenuItem;Llyiahf/vczjk/di5;I)Z

    :cond_1
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
