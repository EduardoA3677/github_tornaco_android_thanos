.class public final synthetic Llyiahf/vczjk/sa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/le3;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/sa;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/sa;->OooOOO:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/sa;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/sa;->OooOOO:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/sa;->OooOOO:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
