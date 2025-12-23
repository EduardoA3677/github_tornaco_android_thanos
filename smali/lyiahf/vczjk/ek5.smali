.class public final synthetic Llyiahf/vczjk/ek5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/zl8;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/le3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/le3;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/ek5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ek5;->OooOOO:Llyiahf/vczjk/zl8;

    iput-object p2, p0, Llyiahf/vczjk/ek5;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ek5;->OooOOO0:I

    check-cast p1, Ljava/lang/Throwable;

    packed-switch v0, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/ek5;->OooOOO:Llyiahf/vczjk/zl8;

    invoke-virtual {p1}, Llyiahf/vczjk/zl8;->OooO0o0()Z

    move-result p1

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/ek5;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/ek5;->OooOOO:Llyiahf/vczjk/zl8;

    invoke-virtual {p1}, Llyiahf/vczjk/zl8;->OooO0o0()Z

    move-result p1

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/ek5;->OooOOOO:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
