.class public final Llyiahf/vczjk/ae0;
.super Llyiahf/vczjk/o76;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ao0;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ao0;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ae0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ae0;->OooOOO:Llyiahf/vczjk/ao0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ae0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/fk7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/fk7;-><init>(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ae0;->OooOOO:Llyiahf/vczjk/ao0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/pc0;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/pc0;-><init>(Ljava/lang/Object;I)V

    iget-object p1, p0, Llyiahf/vczjk/ae0;->OooOOO:Llyiahf/vczjk/ao0;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
