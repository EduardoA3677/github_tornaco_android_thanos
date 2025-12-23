.class public final synthetic Llyiahf/vczjk/zo8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cp8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cp8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/zo8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/zo8;->OooOOO:Llyiahf/vczjk/cp8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 0

    iget p1, p0, Llyiahf/vczjk/zo8;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/zo8;->OooOOO:Llyiahf/vczjk/cp8;

    invoke-virtual {p1}, Llyiahf/vczjk/cp8;->OooO0o()V

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/zo8;->OooOOO:Llyiahf/vczjk/cp8;

    invoke-virtual {p1}, Llyiahf/vczjk/cp8;->OooO0o()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
