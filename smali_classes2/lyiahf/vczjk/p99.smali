.class public final Llyiahf/vczjk/p99;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $featLauncher$inlined:Llyiahf/vczjk/n07;

.field final synthetic $items:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Llyiahf/vczjk/n07;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p99;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/p99;->$featLauncher$inlined:Llyiahf/vczjk/n07;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/eq4;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p4

    and-int/lit8 v0, p4, 0x6

    if-nez v0, :cond_1

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    const/4 p1, 0x2

    :goto_0
    or-int/2addr p1, p4

    goto :goto_1

    :cond_1
    move p1, p4

    :goto_1
    and-int/lit8 p4, p4, 0x30

    if-nez p4, :cond_3

    move-object p4, p3

    check-cast p4, Llyiahf/vczjk/zf1;

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result p4

    if-eqz p4, :cond_2

    const/16 p4, 0x20

    goto :goto_2

    :cond_2
    const/16 p4, 0x10

    :goto_2
    or-int/2addr p1, p4

    :cond_3
    and-int/lit16 p4, p1, 0x93

    const/16 v0, 0x92

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eq p4, v0, :cond_4

    move p4, v1

    goto :goto_3

    :cond_4
    move p4, v2

    :goto_3
    and-int/2addr p1, v1

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, p1, p4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_8

    iget-object p1, p0, Llyiahf/vczjk/p99;->$items:Ljava/util/List;

    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ww2;

    const p2, 0x7043d333

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const p2, 0x4c5de2

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/p99;->$featLauncher$inlined:Llyiahf/vczjk/n07;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p4

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p2, :cond_5

    if-ne p4, v0, :cond_6

    :cond_5
    new-instance p4, Llyiahf/vczjk/oo000o;

    iget-object p2, p0, Llyiahf/vczjk/p99;->$featLauncher$inlined:Llyiahf/vczjk/n07;

    const/16 v1, 0x19

    invoke-direct {p4, p2, v1}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast p4, Llyiahf/vczjk/oe3;

    const p2, 0x6e3c21fe

    invoke-static {p3, v2, p2}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v0, :cond_7

    sget-object p2, Llyiahf/vczjk/iu6;->Oooo0:Llyiahf/vczjk/iu6;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast p2, Llyiahf/vczjk/oe3;

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v0, 0x180

    invoke-static {p1, p4, p2, p3, v0}, Llyiahf/vczjk/yi4;->OooO(Llyiahf/vczjk/ww2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_8
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
