.class public final Llyiahf/vczjk/nk;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;

.field public final OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/nk;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/or1;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Llyiahf/vczjk/nk;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    invoke-static {p2}, Llyiahf/vczjk/jp8;->OoooOo0(Llyiahf/vczjk/or1;)Ljava/lang/Object;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    new-instance p2, Llyiahf/vczjk/j8a;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/j8a;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    iput-object p2, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/qs5;Llyiahf/vczjk/lr5;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/nk;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/nk;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/or1;

    iget-object v1, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/j8a;

    invoke-static {v0, p1, v1, v2, p2}, Llyiahf/vczjk/ng0;->OooooOo(Llyiahf/vczjk/or1;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/n40;

    iget-object p2, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/p29;

    invoke-interface {p2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    const/4 v0, 0x1

    if-le p2, v0, :cond_1

    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v0, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0, p2}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    iget p1, p1, Llyiahf/vczjk/n40;->OooO0OO:F

    iget-object p2, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/lr5;

    check-cast p2, Llyiahf/vczjk/zv8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/j24;

    instance-of p2, p1, Llyiahf/vczjk/wo3;

    iget-object v0, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    if-eqz p2, :cond_2

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    instance-of p2, p1, Llyiahf/vczjk/xo3;

    if-eqz p2, :cond_3

    check-cast p1, Llyiahf/vczjk/xo3;

    iget-object p1, p1, Llyiahf/vczjk/xo3;->OooO00o:Llyiahf/vczjk/wo3;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/g83;

    if-eqz p2, :cond_4

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    instance-of p2, p1, Llyiahf/vczjk/h83;

    if-eqz p2, :cond_5

    check-cast p1, Llyiahf/vczjk/h83;

    iget-object p1, p1, Llyiahf/vczjk/h83;->OooO00o:Llyiahf/vczjk/g83;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_5
    instance-of p2, p1, Llyiahf/vczjk/q37;

    if-eqz p2, :cond_6

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_6
    instance-of p2, p1, Llyiahf/vczjk/r37;

    if-eqz p2, :cond_7

    check-cast p1, Llyiahf/vczjk/r37;

    iget-object p1, p1, Llyiahf/vczjk/r37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_7
    instance-of p2, p1, Llyiahf/vczjk/p37;

    if-eqz p2, :cond_8

    check-cast p1, Llyiahf/vczjk/p37;

    iget-object p1, p1, Llyiahf/vczjk/p37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_8
    :goto_1
    invoke-static {v0}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j24;

    new-instance p2, Llyiahf/vczjk/f33;

    iget-object v0, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/k33;

    const/4 v1, 0x0

    invoke-direct {p2, v0, p1, v1}, Llyiahf/vczjk/f33;-><init>(Llyiahf/vczjk/k33;Llyiahf/vczjk/j24;Llyiahf/vczjk/yo1;)V

    iget-object p1, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    const/4 v0, 0x3

    invoke-static {p1, v1, v1, p2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_9

    iget-object p1, p0, Llyiahf/vczjk/nk;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ze3;

    iget-object p2, p0, Llyiahf/vczjk/nk;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/bz9;

    iget-object v0, p2, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v0}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    iget-object p2, p2, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p2

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    goto :goto_2

    :cond_9
    const/4 p1, 0x0

    :goto_2
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/nk;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/p77;

    check-cast p2, Llyiahf/vczjk/q77;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/q77;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
