.class public final synthetic Llyiahf/vczjk/f52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/g52;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/g52;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/f52;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/f52;->OooOOO:Llyiahf/vczjk/g52;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/f52;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/f52;->OooOOO:Llyiahf/vczjk/g52;

    invoke-static {v0}, Llyiahf/vczjk/g52;->OooO0OO(Llyiahf/vczjk/g52;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/f52;->OooOOO:Llyiahf/vczjk/g52;

    invoke-static {v0}, Llyiahf/vczjk/g52;->OooO0O0(Llyiahf/vczjk/g52;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
