.class public final synthetic Llyiahf/vczjk/bx9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cx9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cx9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bx9;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bx9;->OooOOO:Llyiahf/vczjk/cx9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bx9;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/bx9;->OooOOO:Llyiahf/vczjk/cx9;

    invoke-virtual {v0}, Llyiahf/vczjk/cx9;->OooO00o()V

    return-void

    :pswitch_0
    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/bx9;->OooOOO:Llyiahf/vczjk/cx9;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/cx9;->OooO0OO(Z)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
