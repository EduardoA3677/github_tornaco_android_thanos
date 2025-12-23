.class public final Llyiahf/vczjk/ea2;
.super Llyiahf/vczjk/rc3;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOO:Landroidx/fragment/app/OooOOO;

.field public final synthetic OooOOO0:Llyiahf/vczjk/rc3;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/OooOOO;Llyiahf/vczjk/rc3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ea2;->OooOOO:Landroidx/fragment/app/OooOOO;

    iput-object p2, p0, Llyiahf/vczjk/ea2;->OooOOO0:Llyiahf/vczjk/rc3;

    return-void
.end method


# virtual methods
.method public final OooO0o0(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ea2;->OooOOO0:Llyiahf/vczjk/rc3;

    invoke-virtual {v0}, Llyiahf/vczjk/rc3;->OooOO0o()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rc3;->OooO0o0(I)Landroid/view/View;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ea2;->OooOOO:Landroidx/fragment/app/OooOOO;

    iget-object v0, v0, Landroidx/fragment/app/OooOOO;->OooOo:Landroid/app/Dialog;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Landroid/app/Dialog;->findViewById(I)Landroid/view/View;

    move-result-object p1

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOO0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ea2;->OooOOO0:Llyiahf/vczjk/rc3;

    invoke-virtual {v0}, Llyiahf/vczjk/rc3;->OooOO0o()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ea2;->OooOOO:Landroidx/fragment/app/OooOOO;

    iget-boolean v0, v0, Landroidx/fragment/app/OooOOO;->OooOoo0:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method
