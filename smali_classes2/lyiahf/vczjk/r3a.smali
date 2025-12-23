.class public final Llyiahf/vczjk/r3a;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/t3a;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/t3a;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/r3a;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/r3a;->OooOOO:Llyiahf/vczjk/t3a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/r3a;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/hd7;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/r3a;->OooOOO:Llyiahf/vczjk/t3a;

    iget-object v0, v0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/h87;

    invoke-static {p1, v0}, Llyiahf/vczjk/eo6;->OooOo00(Llyiahf/vczjk/hd7;Llyiahf/vczjk/h87;)Llyiahf/vczjk/hd7;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/r3a;->OooOOO:Llyiahf/vczjk/t3a;

    iget-object v0, v0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rt5;

    invoke-static {v1, p1}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object p1

    iget-boolean v1, p1, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    const-string v1, "<this>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p1}, Llyiahf/vczjk/r02;->OooOOo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/gz0;

    move-result-object p1

    instance-of v0, p1, Llyiahf/vczjk/a3a;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/a3a;

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    :goto_1
    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/r3a;->OooOOO:Llyiahf/vczjk/t3a;

    iget-object v0, v0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rt5;

    invoke-static {v1, p1}, Llyiahf/vczjk/l4a;->OooOo0O(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/hy0;

    move-result-object p1

    iget-boolean v1, p1, Llyiahf/vczjk/hy0;->OooO0OO:Z

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s72;

    if-eqz v1, :cond_2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/s72;->OooO0O0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object p1

    goto :goto_2

    :cond_2
    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-static {v0, p1}, Llyiahf/vczjk/r02;->OooOOo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/gz0;

    move-result-object p1

    :goto_2
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
