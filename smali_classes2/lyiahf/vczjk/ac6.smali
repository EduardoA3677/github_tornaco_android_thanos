.class public final Llyiahf/vczjk/ac6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $import$inlined:Llyiahf/vczjk/oe3;

.field final synthetic $items:Ljava/util/List;

.field final synthetic $reImport$inlined:Llyiahf/vczjk/oe3;

.field final synthetic $update$inlined:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ac6;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/ac6;->$import$inlined:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/ac6;->$reImport$inlined:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/ac6;->$update$inlined:Llyiahf/vczjk/oe3;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

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

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eq p4, v0, :cond_4

    move p4, v2

    goto :goto_3

    :cond_4
    move p4, v1

    :goto_3
    and-int/2addr p1, v2

    move-object v6, p3

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, p1, p4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/ac6;->$items:Ljava/util/List;

    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/cc6;

    const p1, -0x4a2b5ca1

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, p0, Llyiahf/vczjk/ac6;->$import$inlined:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/ac6;->$reImport$inlined:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/ac6;->$update$inlined:Llyiahf/vczjk/oe3;

    const/4 v7, 0x0

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/mc4;->OooOO0(Llyiahf/vczjk/cc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_5
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
