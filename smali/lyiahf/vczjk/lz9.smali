.class public final Llyiahf/vczjk/lz9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pc2;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/bz9;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bz9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/lz9;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/lz9;->OooO0O0:Llyiahf/vczjk/bz9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/lz9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/lz9;->OooO0O0:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooOO0O()V

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v0}, Llyiahf/vczjk/tz9;->OooO0o0()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/lz9;->OooO0O0:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooOO0O()V

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v0}, Llyiahf/vczjk/tz9;->OooO0o0()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
