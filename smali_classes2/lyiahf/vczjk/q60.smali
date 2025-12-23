.class public final Llyiahf/vczjk/q60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Z

.field public final OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/q60;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/q60;->OooOOO:Ljava/lang/Object;

    iput-boolean p4, p0, Llyiahf/vczjk/q60;->OooOOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/q60;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/q60;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/q60;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cg5;

    iget-object v1, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v02;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cg5;->OooO00o(Llyiahf/vczjk/v02;)Llyiahf/vczjk/yd7;

    move-result-object v1

    if-eqz v1, :cond_1

    iget-boolean v2, p0, Llyiahf/vczjk/q60;->OooOOOO:Z

    iget-object v3, p0, Llyiahf/vczjk/q60;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xc7;

    iget-object v0, v0, Llyiahf/vczjk/cg5;->OooO00o:Llyiahf/vczjk/u72;

    if-eqz v2, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    invoke-interface {v0, v1, v3}, Llyiahf/vczjk/zn;->OooOOoo(Llyiahf/vczjk/yd7;Llyiahf/vczjk/xc7;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    goto :goto_0

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    invoke-interface {v0, v1, v3}, Llyiahf/vczjk/zn;->OooO0O0(Llyiahf/vczjk/yd7;Llyiahf/vczjk/xc7;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_2
    return-object v0

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/q60;->OooOOOO:Z

    xor-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/q60;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xw;

    iget-object v2, p0, Llyiahf/vczjk/q60;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/g70;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/g70;->OooOO0o(ZLlyiahf/vczjk/xw;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-boolean v0, p0, Llyiahf/vczjk/q60;->OooOOOO:Z

    xor-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/q60;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xw;

    iget-object v2, p0, Llyiahf/vczjk/q60;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/g70;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/g70;->OooOO0o(ZLlyiahf/vczjk/xw;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    iget-boolean v0, p0, Llyiahf/vczjk/q60;->OooOOOO:Z

    xor-int/lit8 v0, v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/q60;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xw;

    iget-object v2, p0, Llyiahf/vczjk/q60;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/g70;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/g70;->OooOO0o(ZLlyiahf/vczjk/xw;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
