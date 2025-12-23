.class public final Llyiahf/vczjk/qt;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ov5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ov5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/qt;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/qt;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Llyiahf/vczjk/ku5;

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    const-string p4, "$this$animatedComposable"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "it"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/qt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p4

    if-nez p2, :cond_0

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p4, p2, :cond_1

    :cond_0
    new-instance p4, Llyiahf/vczjk/pt;

    const/4 p2, 0x5

    invoke-direct {p4, p1, p2}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast p4, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p4, p3, p1}, Llyiahf/vczjk/so8;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Llyiahf/vczjk/ku5;

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    const-string p4, "$this$animatedComposable"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "it"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/qt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p4

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p4, p2, :cond_3

    :cond_2
    new-instance p4, Llyiahf/vczjk/pt;

    const/4 p2, 0x4

    invoke-direct {p4, p1, p2}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast p4, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p4, p3, p1}, Llyiahf/vczjk/ru6;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Llyiahf/vczjk/ku5;

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    const-string p4, "$this$animatedComposable"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "it"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/qt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p4

    if-nez p2, :cond_4

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p4, p2, :cond_5

    :cond_4
    new-instance p4, Llyiahf/vczjk/pt;

    const/4 p2, 0x3

    invoke-direct {p4, p1, p2}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast p4, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p4, p3, p1}, Llyiahf/vczjk/vt6;->OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Llyiahf/vczjk/ku5;

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    const-string p4, "$this$composable"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "it"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/qt;->OooOOO:Llyiahf/vczjk/ov5;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p4

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p4, :cond_6

    if-ne v0, v1, :cond_7

    :cond_6
    new-instance v0, Llyiahf/vczjk/pt;

    const/4 p4, 0x0

    invoke-direct {v0, p2, p4}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v0, Llyiahf/vczjk/le3;

    const/4 p4, 0x0

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_8

    if-ne v3, v1, :cond_9

    :cond_8
    new-instance v3, Llyiahf/vczjk/pt;

    const/4 v2, 0x1

    invoke-direct {v3, p2, v2}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez p1, :cond_a

    if-ne v2, v1, :cond_b

    :cond_a
    new-instance v2, Llyiahf/vczjk/pt;

    const/4 p1, 0x2

    invoke-direct {v2, p2, p1}, Llyiahf/vczjk/pt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v3, v2, p3, p4}, Llyiahf/vczjk/ng0;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

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
