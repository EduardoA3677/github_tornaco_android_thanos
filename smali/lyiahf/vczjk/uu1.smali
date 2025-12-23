.class public final Llyiahf/vczjk/uu1;
.super Llyiahf/vczjk/on2;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nn2;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/uu1;->OooO0o0:I

    invoke-direct {p0, p1}, Llyiahf/vczjk/on2;-><init>(Llyiahf/vczjk/nn2;)V

    return-void
.end method


# virtual methods
.method public OooOOo()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/uu1;->OooO0o0:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/on2;->OooO0O0:Llyiahf/vczjk/nn2;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/nn2;->OooOoOO:Landroid/view/View$OnLongClickListener;

    iget-object v0, v0, Llyiahf/vczjk/nn2;->OooOOoo:Lcom/google/android/material/internal/CheckableImageButton;

    invoke-virtual {v0, v1}, Landroid/view/View;->setOnLongClickListener(Landroid/view/View$OnLongClickListener;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/jp8;->o000oOoO(Lcom/google/android/material/internal/CheckableImageButton;Landroid/view/View$OnLongClickListener;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
