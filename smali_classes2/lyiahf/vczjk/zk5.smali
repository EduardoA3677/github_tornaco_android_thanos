.class public final synthetic Llyiahf/vczjk/zk5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/al5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/al5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/zk5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/zk5;->OooOOO:Llyiahf/vczjk/al5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 0

    iget p1, p0, Llyiahf/vczjk/zk5;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/zk5;->OooOOO:Llyiahf/vczjk/al5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/zk5;->OooOOO:Llyiahf/vczjk/al5;

    iget-object p1, p1, Llyiahf/vczjk/al5;->OooO0o:Ljava/lang/Runnable;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    :cond_0
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
