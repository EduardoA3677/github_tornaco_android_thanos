.class public final Llyiahf/vczjk/d67;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/t67;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/d67;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/d67;->OooOOO:Llyiahf/vczjk/t67;

    iput-object p2, p0, Llyiahf/vczjk/d67;->OooOOOO:Llyiahf/vczjk/oe3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/d67;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p2

    const-string p4, "$this$stickyHeader"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 p1, p2, 0x81

    const/16 p2, 0x80

    if-ne p1, p2, :cond_1

    move-object p1, p3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/d67;->OooOOO:Llyiahf/vczjk/t67;

    iget-object p2, p1, Llyiahf/vczjk/t67;->OooO0o0:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    iget-object p4, p0, Llyiahf/vczjk/d67;->OooOOOO:Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    iget-boolean p1, p1, Llyiahf/vczjk/t67;->OooOO0O:Z

    invoke-static {p2, p1, p4, p3, v0}, Llyiahf/vczjk/xt6;->OooOO0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p2

    const-string p4, "$this$stickyHeader"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 p1, p2, 0x81

    const/16 p2, 0x80

    if-ne p1, p2, :cond_3

    move-object p1, p3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/d67;->OooOOO:Llyiahf/vczjk/t67;

    iget-object p2, p1, Llyiahf/vczjk/t67;->OooO0Oo:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    iget-object p4, p0, Llyiahf/vczjk/d67;->OooOOOO:Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    iget-boolean p1, p1, Llyiahf/vczjk/t67;->OooOO0:Z

    invoke-static {p2, p1, p4, p3, v0}, Llyiahf/vczjk/xt6;->OooO0o0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p2

    const-string p4, "$this$stickyHeader"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 p1, p2, 0x81

    const/16 p2, 0x80

    if-ne p1, p2, :cond_5

    move-object p1, p3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_5
    :goto_4
    iget-object p1, p0, Llyiahf/vczjk/d67;->OooOOO:Llyiahf/vczjk/t67;

    iget-object p2, p1, Llyiahf/vczjk/t67;->OooO0OO:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    iget-object p4, p0, Llyiahf/vczjk/d67;->OooOOOO:Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    iget-boolean p1, p1, Llyiahf/vczjk/t67;->OooO:Z

    invoke-static {p2, p1, p4, p3, v0}, Llyiahf/vczjk/xt6;->OooOOOo(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
