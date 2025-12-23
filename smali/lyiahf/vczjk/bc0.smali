.class public final synthetic Llyiahf/vczjk/bc0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/jc0;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/jc0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bc0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bc0;->OooOOO:Llyiahf/vczjk/jc0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bc0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/bc0;->OooOOO:Llyiahf/vczjk/jc0;

    iget-object v0, v0, Llyiahf/vczjk/jc0;->OooOOO0:Llyiahf/vczjk/tc0;

    iget-object v1, v0, Llyiahf/vczjk/tc0;->OooO0OO:Llyiahf/vczjk/r02;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/qc0;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/tc0;->OooO0OO:Llyiahf/vczjk/r02;

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/tc0;->OooO0OO:Llyiahf/vczjk/r02;

    invoke-virtual {v0}, Llyiahf/vczjk/r02;->OooOoO()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/bc0;->OooOOO:Llyiahf/vczjk/jc0;

    iget-object v0, v0, Llyiahf/vczjk/jc0;->OooOOO0:Llyiahf/vczjk/tc0;

    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/tc0;->OooOoO0:Z

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
