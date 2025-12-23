.class public final Llyiahf/vczjk/qd0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cy8;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/qd0;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/wc5;Llyiahf/vczjk/pi4;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/qd0;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance p2, Llyiahf/vczjk/pd0;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    const/4 v0, 0x1

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/pd0;-><init>(Llyiahf/vczjk/bd5;I)V

    return-object p2

    :pswitch_0
    new-instance p1, Llyiahf/vczjk/nm2;

    const/4 p2, 0x1

    invoke-direct {p1, p2}, Llyiahf/vczjk/nm2;-><init>(I)V

    return-object p1

    :pswitch_1
    new-instance p1, Landroid/text/style/StrikethroughSpan;

    invoke-direct {p1}, Landroid/text/style/StrikethroughSpan;-><init>()V

    return-object p1

    :pswitch_2
    sget-object v0, Llyiahf/vczjk/mp1;->OooOOO0:Llyiahf/vczjk/mp1;

    sget-object v1, Llyiahf/vczjk/t51;->OooO00o:Llyiahf/vczjk/ja7;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object v1

    if-ne v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/ok0;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    sget-object v1, Llyiahf/vczjk/t51;->OooO0O0:Llyiahf/vczjk/ja7;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ok0;-><init>(Llyiahf/vczjk/bd5;I)V

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/t51;->OooO0OO:Llyiahf/vczjk/ja7;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object p2

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    const-string v0, ".\u00a0"

    invoke-virtual {p2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/jf6;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/jf6;-><init>(Llyiahf/vczjk/bd5;Ljava/lang/String;)V

    :goto_0
    return-object v0

    :pswitch_3
    new-instance v0, Lio/noties/markwon/core/spans/LinkSpan;

    iget-object v1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    sget-object v2, Llyiahf/vczjk/t51;->OooO0o0:Llyiahf/vczjk/ja7;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/String;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO0Oo:Llyiahf/vczjk/h05;

    invoke-direct {v0, v1, p2, p1}, Lio/noties/markwon/core/spans/LinkSpan;-><init>(Llyiahf/vczjk/bd5;Ljava/lang/String;Llyiahf/vczjk/h05;)V

    return-object v0

    :pswitch_4
    new-instance v0, Llyiahf/vczjk/sz;

    iget-object v1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    new-instance v2, Llyiahf/vczjk/oz;

    sget-object v3, Llyiahf/vczjk/e16;->OooO0OO:Llyiahf/vczjk/ja7;

    invoke-virtual {v3, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    sget-object v4, Llyiahf/vczjk/e16;->OooO0o0:Llyiahf/vczjk/ja7;

    iget-object p2, p2, Llyiahf/vczjk/pi4;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {p2, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/mv3;

    iget-object v5, p1, Llyiahf/vczjk/wc5;->OooO0O0:Llyiahf/vczjk/v34;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO0o:Llyiahf/vczjk/rp3;

    invoke-direct {v2, v3, v5, p1, v4}, Llyiahf/vczjk/oz;-><init>(Ljava/lang/String;Llyiahf/vczjk/v34;Llyiahf/vczjk/rp3;Llyiahf/vczjk/mv3;)V

    sget-object p1, Llyiahf/vczjk/e16;->OooO0Oo:Llyiahf/vczjk/ja7;

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p2, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_1

    move-object v3, p1

    :cond_1
    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/sz;-><init>(Llyiahf/vczjk/bd5;Llyiahf/vczjk/oz;Z)V

    return-object v0

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/ym3;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    sget-object v1, Llyiahf/vczjk/t51;->OooO0Oo:Llyiahf/vczjk/ja7;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/ja7;->OooO00o(Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ym3;-><init>(Llyiahf/vczjk/bd5;I)V

    return-object v0

    :pswitch_6
    new-instance p1, Llyiahf/vczjk/nm2;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Llyiahf/vczjk/nm2;-><init>(I)V

    return-object p1

    :pswitch_7
    new-instance p2, Llyiahf/vczjk/z01;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/z01;-><init>(Ljava/lang/Object;I)V

    return-object p2

    :pswitch_8
    new-instance p2, Llyiahf/vczjk/w01;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    invoke-direct {p2, p1}, Llyiahf/vczjk/w01;-><init>(Llyiahf/vczjk/bd5;)V

    return-object p2

    :pswitch_9
    new-instance p2, Llyiahf/vczjk/pd0;

    iget-object p1, p1, Llyiahf/vczjk/wc5;->OooO00o:Llyiahf/vczjk/bd5;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/pd0;-><init>(Llyiahf/vczjk/bd5;I)V

    return-object p2

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
