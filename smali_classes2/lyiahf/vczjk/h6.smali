.class public final synthetic Llyiahf/vczjk/h6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ec9;
.implements Llyiahf/vczjk/vw9;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/i6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/i6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h6;->OooOOO0:Llyiahf/vczjk/i6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooOOOo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h6;->OooOOO0:Llyiahf/vczjk/i6;

    iget-object v0, v0, Llyiahf/vczjk/i6;->OooOOO:Llyiahf/vczjk/k6;

    invoke-virtual {v0}, Llyiahf/vczjk/k6;->OooO0oO()V

    return-void
.end method

.method public onMenuItemClick(Landroid/view/MenuItem;)Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/h6;->OooOOO0:Llyiahf/vczjk/i6;

    sget v1, Lgithub/tornaco/android/thanos/R$id;->action_reset_all_modes:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result p1

    if-ne v1, p1, :cond_0

    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-virtual {v0}, Landroidx/fragment/app/Oooo0;->requireActivity()Landroidx/fragment/app/FragmentActivity;

    move-result-object v1

    invoke-direct {p1, v1}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_ops_title_reset_ops_mode_for_all:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->common_dialog_message_are_you_sure:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    new-instance v1, Llyiahf/vczjk/w0;

    const/4 v2, 0x1

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    const v0, 0x104000a

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    const/high16 v0, 0x1040000

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
