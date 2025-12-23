.class public final synthetic Llyiahf/vczjk/fa;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/fa;->OooOOO:I

    move-object p7, p4

    move-object p4, p3

    move p3, p6

    move-object p6, p7

    move-object p7, p5

    move-object p5, p2

    move p2, p1

    move-object p1, p0

    invoke-direct/range {p1 .. p7}, Llyiahf/vczjk/vf3;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/fa;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/uk4;

    check-cast p2, Llyiahf/vczjk/uk4;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "p1"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v06;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/uk4;

    check-cast p2, Llyiahf/vczjk/uk4;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "p1"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/k4a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/u06;->OooO0O0:Llyiahf/vczjk/t06;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/t06;->OooO0O0:Llyiahf/vczjk/v06;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/v06;->OooO0O0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/v06;->OooO0O0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/z83;

    check-cast p2, Llyiahf/vczjk/z83;

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/n93;

    iget-boolean v1, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_1

    goto/16 :goto_3

    :cond_1
    check-cast p2, Llyiahf/vczjk/a93;

    invoke-virtual {p2}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result p2

    check-cast p1, Llyiahf/vczjk/a93;

    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result p1

    if-ne p2, p1, :cond_2

    goto/16 :goto_3

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/n93;->OooOooO:Llyiahf/vczjk/o00000;

    if-eqz p1, :cond_3

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    const/4 p1, 0x0

    if-eqz p2, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/l93;

    invoke-direct {v2, v0, p1}, Llyiahf/vczjk/l93;-><init>(Llyiahf/vczjk/n93;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v1, p1, p1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/m93;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/m93;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/n93;)V

    invoke-static {v0, v2}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eu4;

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/eu4;->OooO00o()Llyiahf/vczjk/eu4;

    goto :goto_1

    :cond_4
    move-object v1, p1

    :goto_1
    iput-object v1, v0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    iget-object v1, v0, Llyiahf/vczjk/n93;->Oooo00O:Llyiahf/vczjk/v16;

    if-eqz v1, :cond_7

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/n93;->o00000oO()Llyiahf/vczjk/o93;

    move-result-object v1

    if-eqz v1, :cond_7

    iget-object v2, v0, Llyiahf/vczjk/n93;->Oooo00O:Llyiahf/vczjk/v16;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/o93;->o00000OO(Llyiahf/vczjk/xn4;)V

    goto :goto_2

    :cond_5
    iget-object v1, v0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    if-eqz v1, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/eu4;->OooO0O0()V

    :cond_6
    iput-object p1, v0, Llyiahf/vczjk/n93;->Oooo000:Llyiahf/vczjk/eu4;

    invoke-virtual {v0}, Llyiahf/vczjk/n93;->o00000oO()Llyiahf/vczjk/o93;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o93;->o00000OO(Llyiahf/vczjk/xn4;)V

    :cond_7
    :goto_2
    invoke-static {v0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    iget-object v1, v0, Llyiahf/vczjk/n93;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v1, :cond_a

    if-eqz p2, :cond_9

    iget-object p2, v0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    if-eqz p2, :cond_8

    new-instance v2, Llyiahf/vczjk/h83;

    invoke-direct {v2, p2}, Llyiahf/vczjk/h83;-><init>(Llyiahf/vczjk/g83;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n93;->o0000Ooo(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V

    iput-object p1, v0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    :cond_8
    new-instance p1, Llyiahf/vczjk/g83;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/n93;->o0000Ooo(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V

    iput-object p1, v0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    goto :goto_3

    :cond_9
    iget-object p2, v0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    if-eqz p2, :cond_a

    new-instance v2, Llyiahf/vczjk/h83;

    invoke-direct {v2, p2}, Llyiahf/vczjk/h83;-><init>(Llyiahf/vczjk/g83;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n93;->o0000Ooo(Llyiahf/vczjk/rr5;Llyiahf/vczjk/j24;)V

    iput-object p1, v0, Llyiahf/vczjk/n93;->OooOooo:Llyiahf/vczjk/g83;

    :cond_a
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/b83;

    check-cast p2, Llyiahf/vczjk/wj7;

    iget-object v0, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/xa;->OooO0oo(Llyiahf/vczjk/xa;Llyiahf/vczjk/b83;Llyiahf/vczjk/wj7;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
