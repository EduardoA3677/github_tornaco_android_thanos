.class public final Llyiahf/vczjk/gt4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/uy5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/uy5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/gt4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/gt4;->OooOOO:Llyiahf/vczjk/uy5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/gt4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p2, Llyiahf/vczjk/ut4;

    invoke-interface {p2}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/gt4;->OooOOO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    check-cast p1, Llyiahf/vczjk/ut4;

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/os9;->OooOOo(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    move-result p1

    return p1

    :pswitch_0
    check-cast p2, Llyiahf/vczjk/ut4;

    invoke-interface {p2}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/gt4;->OooOOO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    check-cast p1, Llyiahf/vczjk/ut4;

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/os9;->OooOOo(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    move-result p1

    return p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/ut4;

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/gt4;->OooOOO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    check-cast p2, Llyiahf/vczjk/ut4;

    invoke-interface {p2}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v0, p2}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/os9;->OooOOo(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    move-result p1

    return p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/ut4;

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/gt4;->OooOOO:Llyiahf/vczjk/uy5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    check-cast p2, Llyiahf/vczjk/ut4;

    invoke-interface {p2}, Llyiahf/vczjk/ut4;->getKey()Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v0, p2}, Llyiahf/vczjk/uy5;->OooO00o(Ljava/lang/Object;)I

    move-result p2

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/os9;->OooOOo(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    move-result p1

    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
