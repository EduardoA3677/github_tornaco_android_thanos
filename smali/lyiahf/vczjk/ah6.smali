.class public final Llyiahf/vczjk/ah6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dh6;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/eh6;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/eh6;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ah6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ah6;->OooOOO:Llyiahf/vczjk/eh6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ah6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ah6;->OooOOO:Llyiahf/vczjk/eh6;

    iget-object v1, v0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/yn;->OooOoO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/t66;

    move-result-object v1

    if-eqz v1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/yn;->OooOoO(Llyiahf/vczjk/u34;Llyiahf/vczjk/t66;)Llyiahf/vczjk/t66;

    move-result-object v1

    :cond_0
    return-object v1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ah6;->OooOOO:Llyiahf/vczjk/eh6;

    iget-object v0, v0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yn;->Oooo0o0(Llyiahf/vczjk/pm;)Llyiahf/vczjk/xn;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
