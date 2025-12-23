.class public final synthetic Llyiahf/vczjk/t85;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u85;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/v85;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/v85;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/t85;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/t85;->OooO0O0:Llyiahf/vczjk/v85;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t85;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/t85;->OooO0O0:Llyiahf/vczjk/v85;

    invoke-virtual {v0}, Llyiahf/vczjk/v85;->OooOO0o()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/t85;->OooO0O0:Llyiahf/vczjk/v85;

    invoke-virtual {v0}, Llyiahf/vczjk/v85;->OooOOO()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
