.class public final synthetic Llyiahf/vczjk/aa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnTouchModeChangeListener;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/xa;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/aa;->OooOOO0:Llyiahf/vczjk/xa;

    return-void
.end method


# virtual methods
.method public final onTouchModeChanged(Z)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/aa;->OooOOO0:Llyiahf/vczjk/xa;

    iget-object v0, v0, Llyiahf/vczjk/xa;->o0OOO0o:Llyiahf/vczjk/u04;

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x2

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/u04;->OooO00o:Llyiahf/vczjk/qs5;

    new-instance v1, Llyiahf/vczjk/s04;

    invoke-direct {v1, p1}, Llyiahf/vczjk/s04;-><init>(I)V

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method
