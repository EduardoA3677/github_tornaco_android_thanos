.class public final Llyiahf/vczjk/z5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Ljava/util/List;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo:Landroidx/appcompat/app/AppCompatActivity;

.field public final synthetic OooOOo0:Llyiahf/vczjk/ww2;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ww2;Landroidx/appcompat/app/AppCompatActivity;I)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/z5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/z5;->OooOOO:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/z5;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/z5;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/z5;->OooOOo0:Llyiahf/vczjk/ww2;

    iput-object p5, p0, Llyiahf/vczjk/z5;->OooOOo:Landroidx/appcompat/app/AppCompatActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/z5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/q31;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    const-string v0, "$this$DropdownMenu"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p1, p3, 0x11

    const/16 p3, 0x10

    if-ne p1, p3, :cond_1

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p3

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2

    :cond_1
    :goto_0
    move-object v6, p2

    check-cast v6, Llyiahf/vczjk/zf1;

    const p1, -0x1657560d

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/z5;->OooOOO:Ljava/util/List;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const v0, -0x6815fd56

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/z5;->OooOOOO:Llyiahf/vczjk/qs5;

    if-eqz p2, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/xn6;

    new-instance v3, Llyiahf/vczjk/y5;

    const/4 v4, 0x1

    invoke-direct {v3, p2, v4}, Llyiahf/vczjk/y5;-><init>(Llyiahf/vczjk/xn6;I)V

    const v4, -0x14a9c69e

    invoke-static {v4, v3, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v0, v4

    iget-object v4, p0, Llyiahf/vczjk/z5;->OooOOo:Landroidx/appcompat/app/AppCompatActivity;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v0, v5

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_2

    if-ne v5, p3, :cond_3

    :cond_2
    new-instance v5, Llyiahf/vczjk/o0O0000O;

    const/4 p3, 0x4

    invoke-direct {v5, p2, v4, p3, v2}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x6

    const/16 v8, 0x1fc

    const/4 v2, 0x0

    move-object v0, v3

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v1, v5

    const/4 v5, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    goto :goto_1

    :cond_4
    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move p1, v0

    sget-object v0, Llyiahf/vczjk/za1;->OooO0O0:Llyiahf/vczjk/a91;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/z5;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr p1, v3

    iget-object v3, p0, Llyiahf/vczjk/z5;->OooOOo0:Llyiahf/vczjk/ww2;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr p1, v4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez p1, :cond_5

    if-ne v4, p3, :cond_6

    :cond_5
    new-instance v4, Llyiahf/vczjk/o0O0000O;

    const/4 p1, 0x5

    invoke-direct {v4, p2, v3, p1, v2}, Llyiahf/vczjk/o0O0000O;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x6

    const/16 v8, 0x1fc

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v1, v4

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/q31;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    const-string v0, "$this$DropdownMenu"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p1, p3, 0x11

    const/16 p3, 0x10

    if-ne p1, p3, :cond_8

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p3

    if-nez p3, :cond_7

    goto :goto_3

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_8
    :goto_3
    move-object v6, p2

    check-cast v6, Llyiahf/vczjk/zf1;

    const p1, 0x66b90989

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/z5;->OooOOO:Ljava/util/List;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-object v0, p0, Llyiahf/vczjk/z5;->OooOOOO:Llyiahf/vczjk/qs5;

    const v1, -0x6815fd56

    const/4 v2, 0x0

    if-eqz p2, :cond_b

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/xn6;

    new-instance v3, Llyiahf/vczjk/y5;

    const/4 v4, 0x0

    invoke-direct {v3, p2, v4}, Llyiahf/vczjk/y5;-><init>(Llyiahf/vczjk/xn6;I)V

    const v4, 0x554f2ca0

    invoke-static {v4, v3, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    iget-object v4, p0, Llyiahf/vczjk/z5;->OooOOo:Landroidx/appcompat/app/AppCompatActivity;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v1, v5

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v1, :cond_9

    if-ne v5, p3, :cond_a

    :cond_9
    new-instance v5, Llyiahf/vczjk/x5;

    const/4 p3, 0x0

    invoke-direct {v5, p2, v4, p3, v0}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v1, v5

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x6

    const/16 v8, 0x1fc

    const/4 v2, 0x0

    move-object v0, v3

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    goto :goto_4

    :cond_b
    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object p1, v0

    sget-object v0, Llyiahf/vczjk/e91;->OooO0O0:Llyiahf/vczjk/a91;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    iget-object v1, p0, Llyiahf/vczjk/z5;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr p2, v3

    iget-object v3, p0, Llyiahf/vczjk/z5;->OooOOo0:Llyiahf/vczjk/ww2;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr p2, v4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez p2, :cond_c

    if-ne v4, p3, :cond_d

    :cond_c
    new-instance v4, Llyiahf/vczjk/x5;

    const/4 p2, 0x1

    invoke-direct {v4, v1, v3, p2, p1}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    move-object v1, v4

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x6

    const/16 v8, 0x1fc

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
