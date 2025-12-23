.class public final Llyiahf/vczjk/fh5;
.super Llyiahf/vczjk/oO000OOo;
.source "SourceFile"

# interfaces
.implements Landroid/view/ActionProvider$VisibilityListener;


# instance fields
.field public OooO0O0:Llyiahf/vczjk/tqa;

.field public final OooO0OO:Landroid/view/ActionProvider;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/ih5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ih5;Landroid/view/ActionProvider;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fh5;->OooO0Oo:Llyiahf/vczjk/ih5;

    iput-object p2, p0, Llyiahf/vczjk/fh5;->OooO0OO:Landroid/view/ActionProvider;

    return-void
.end method


# virtual methods
.method public final onActionProviderVisibilityChanged(Z)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/fh5;->OooO0O0:Llyiahf/vczjk/tqa;

    if-eqz p1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/tqa;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/dh5;

    iget-object p1, p1, Llyiahf/vczjk/dh5;->OooOOO:Llyiahf/vczjk/sg5;

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/sg5;->OooO0oo:Z

    invoke-virtual {p1, v0}, Llyiahf/vczjk/sg5;->OooOOOo(Z)V

    :cond_0
    return-void
.end method
