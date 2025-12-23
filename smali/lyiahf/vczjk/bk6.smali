.class public final Llyiahf/vczjk/bk6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/km6;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/km6;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bk6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bk6;->OooOOO:Llyiahf/vczjk/km6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget p2, p0, Llyiahf/vczjk/bk6;->OooOOO0:I

    packed-switch p2, :pswitch_data_0

    check-cast p1, Ljava/lang/Integer;

    iget-object p1, p0, Llyiahf/vczjk/bk6;->OooOOO:Llyiahf/vczjk/km6;

    invoke-virtual {p1}, Llyiahf/vczjk/km6;->OooO0oO()Llyiahf/vczjk/gv4;

    move-result-object p2

    if-eqz p2, :cond_0

    check-cast p2, Llyiahf/vczjk/tv4;

    invoke-virtual {p1}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v0

    iget p2, p2, Llyiahf/vczjk/tv4;->OooO00o:I

    if-eq p2, v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/km6;->OooO0O0:Llyiahf/vczjk/qs5;

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p0, Llyiahf/vczjk/bk6;->OooOOO:Llyiahf/vczjk/km6;

    iget-object p1, p1, Llyiahf/vczjk/km6;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
