.class public final Llyiahf/vczjk/uy;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Iterable;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/uy;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/uy;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/uy;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/uy;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wf8;

    invoke-interface {v0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/zi2;

    iget-object v1, p0, Llyiahf/vczjk/uy;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-interface {v1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Iterator;

    invoke-direct {v0, v1}, Llyiahf/vczjk/zi2;-><init>(Ljava/util/Iterator;)V

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/uy;->OooOOO:Ljava/lang/Object;

    check-cast v0, [Ljava/lang/Object;

    invoke-static {v0}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
