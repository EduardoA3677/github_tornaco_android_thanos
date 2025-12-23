.class public final Llyiahf/vczjk/tr;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yr;
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public OooOOO:Llyiahf/vczjk/ur;

.field public OooOOO0:Llyiahf/vczjk/x3;

.field public OooOOOO:Ljava/lang/CharSequence;

.field public final synthetic OooOOOo:Landroidx/appcompat/widget/AppCompatSpinner;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/AppCompatSpinner;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tr;->OooOOOo:Landroidx/appcompat/widget/AppCompatSpinner;

    return-void
.end method


# virtual methods
.method public final OooO(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set popup background for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tr;->OooOOO0:Llyiahf/vczjk/x3;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/app/Dialog;->isShowing()Z

    move-result v0

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0O0()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0OO(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set horizontal offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public final OooO0o()Landroid/graphics/drawable/Drawable;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tr;->OooOOOO:Ljava/lang/CharSequence;

    return-object v0
.end method

.method public final OooO0oO(Ljava/lang/CharSequence;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tr;->OooOOOO:Ljava/lang/CharSequence;

    return-void
.end method

.method public final OooOO0(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set vertical offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public final OooOO0o(I)V
    .locals 1

    const-string p1, "AppCompatSpinner"

    const-string v0, "Cannot set horizontal (original) offset for MODE_DIALOG, ignoring"

    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public final OooOOO(II)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/tr;->OooOOO:Llyiahf/vczjk/ur;

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/w3;

    iget-object v1, p0, Llyiahf/vczjk/tr;->OooOOOo:Landroidx/appcompat/widget/AppCompatSpinner;

    invoke-virtual {v1}, Landroidx/appcompat/widget/AppCompatSpinner;->getPopupContext()Landroid/content/Context;

    move-result-object v2

    invoke-direct {v0, v2}, Llyiahf/vczjk/w3;-><init>(Landroid/content/Context;)V

    iget-object v2, p0, Llyiahf/vczjk/tr;->OooOOOO:Ljava/lang/CharSequence;

    iget-object v3, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s3;

    if-eqz v2, :cond_1

    iput-object v2, v3, Llyiahf/vczjk/s3;->OooO0Oo:Ljava/lang/CharSequence;

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/tr;->OooOOO:Llyiahf/vczjk/ur;

    invoke-virtual {v1}, Landroid/widget/AdapterView;->getSelectedItemPosition()I

    move-result v1

    iput-object v2, v3, Llyiahf/vczjk/s3;->OooOOo0:Ljava/lang/Object;

    iput-object p0, v3, Llyiahf/vczjk/s3;->OooOOo:Landroid/content/DialogInterface$OnClickListener;

    iput v1, v3, Llyiahf/vczjk/s3;->OooOo:I

    const/4 v1, 0x1

    iput-boolean v1, v3, Llyiahf/vczjk/s3;->OooOo0o:Z

    invoke-virtual {v0}, Llyiahf/vczjk/w3;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/tr;->OooOOO0:Llyiahf/vczjk/x3;

    iget-object v0, v0, Llyiahf/vczjk/x3;->OooOOo:Llyiahf/vczjk/v3;

    iget-object v0, v0, Llyiahf/vczjk/v3;->OooO0o:Landroidx/appcompat/app/AlertController$RecycleListView;

    invoke-virtual {v0, p1}, Landroid/view/View;->setTextDirection(I)V

    invoke-virtual {v0, p2}, Landroid/view/View;->setTextAlignment(I)V

    iget-object p1, p0, Llyiahf/vczjk/tr;->OooOOO0:Llyiahf/vczjk/x3;

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return-void
.end method

.method public final OooOOOO()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOOo(Landroid/widget/ListAdapter;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/ur;

    iput-object p1, p0, Llyiahf/vczjk/tr;->OooOOO:Llyiahf/vczjk/ur;

    return-void
.end method

.method public final dismiss()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tr;->OooOOO0:Llyiahf/vczjk/x3;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/x3;->dismiss()V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/tr;->OooOOO0:Llyiahf/vczjk/x3;

    :cond_0
    return-void
.end method

.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 3

    iget-object p1, p0, Llyiahf/vczjk/tr;->OooOOOo:Landroidx/appcompat/widget/AppCompatSpinner;

    invoke-virtual {p1, p2}, Landroid/widget/AdapterView;->setSelection(I)V

    invoke-virtual {p1}, Landroid/widget/AdapterView;->getOnItemClickListener()Landroid/widget/AdapterView$OnItemClickListener;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tr;->OooOOO:Llyiahf/vczjk/ur;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/ur;->getItemId(I)J

    move-result-wide v0

    const/4 v2, 0x0

    invoke-virtual {p1, v2, p2, v0, v1}, Landroid/widget/AdapterView;->performItemClick(Landroid/view/View;IJ)Z

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/tr;->dismiss()V

    return-void
.end method
