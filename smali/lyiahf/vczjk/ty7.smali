.class public final synthetic Llyiahf/vczjk/ty7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/ny7;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ny7;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/ty7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ty7;->OooOOO:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/ty7;->OooOOOO:Llyiahf/vczjk/ny7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ty7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ty7;->OooOOOO:Llyiahf/vczjk/ny7;

    iget-boolean v0, v0, Llyiahf/vczjk/ny7;->OooO:Z

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ty7;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ty7;->OooOOOO:Llyiahf/vczjk/ny7;

    iget-boolean v0, v0, Llyiahf/vczjk/ny7;->OooO:Z

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ty7;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
