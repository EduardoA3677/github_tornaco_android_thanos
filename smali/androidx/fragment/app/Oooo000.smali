.class public final Landroidx/fragment/app/Oooo000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOO0:Landroidx/fragment/app/Oooo0;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/Oooo0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/fragment/app/Oooo000;->OooOOO0:Landroidx/fragment/app/Oooo0;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 0

    sget-object p1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_0

    iget-object p1, p0, Landroidx/fragment/app/Oooo000;->OooOOO0:Landroidx/fragment/app/Oooo0;

    iget-object p1, p1, Landroidx/fragment/app/Oooo0;->mView:Landroid/view/View;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Landroid/view/View;->cancelPendingInputEvents()V

    :cond_0
    return-void
.end method
