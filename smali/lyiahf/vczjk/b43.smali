.class public final synthetic Llyiahf/vczjk/b43;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/b43;->OooOOO0:I

    sget-object v0, Llyiahf/vczjk/mi2;->OooOOO0:Llyiahf/vczjk/mi2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b43;->OooOOO:Llyiahf/vczjk/oe3;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/b43;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/b43;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/b43;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ki2;

    sget-object v1, Llyiahf/vczjk/mi2;->OooOOO0:Llyiahf/vczjk/mi2;

    iget-object v2, p0, Llyiahf/vczjk/b43;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ki2;-><init>(Llyiahf/vczjk/mi2;Llyiahf/vczjk/oe3;)V

    return-object v0

    :pswitch_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/b43;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0

    :pswitch_1
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/b43;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
