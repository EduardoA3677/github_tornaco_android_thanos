.class public final Llyiahf/vczjk/i13;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Landroidx/fragment/app/OooOOO;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Landroidx/fragment/app/OooOOO;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/i13;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/i13;->OooOOO:Landroidx/fragment/app/OooOOO;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/i13;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/i13;->OooOOO:Landroidx/fragment/app/OooOOO;

    check-cast v0, Llyiahf/vczjk/m15;

    iput p2, v0, Llyiahf/vczjk/m15;->Oooo0OO:I

    const/4 p2, -0x1

    iput p2, v0, Llyiahf/vczjk/h27;->Oooo0O0:I

    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/i13;->OooOOO:Landroidx/fragment/app/OooOOO;

    check-cast p1, Llyiahf/vczjk/m13;

    iget-object p1, p1, Llyiahf/vczjk/m13;->OooOooo:Llyiahf/vczjk/tc0;

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tc0;->OooO0oo(Z)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
