.class public final Llyiahf/vczjk/o51;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $items:Ljava/util/List;

.field final synthetic $sortState$inlined:Llyiahf/vczjk/yp7;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/yp7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o51;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/o51;->$sortState$inlined:Llyiahf/vczjk/yp7;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    move-object v0, p1

    check-cast v0, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p4, p2, 0x6

    if-nez p4, :cond_1

    move-object p4, p3

    check-cast p4, Llyiahf/vczjk/zf1;

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p4

    if-eqz p4, :cond_0

    const/4 p4, 0x4

    goto :goto_0

    :cond_0
    const/4 p4, 0x2

    :goto_0
    or-int/2addr p4, p2

    goto :goto_1

    :cond_1
    move p4, p2

    :goto_1
    and-int/lit8 p2, p2, 0x30

    if-nez p2, :cond_3

    move-object p2, p3

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result p2

    if-eqz p2, :cond_2

    const/16 p2, 0x20

    goto :goto_2

    :cond_2
    const/16 p2, 0x10

    :goto_2
    or-int/2addr p4, p2

    :cond_3
    and-int/lit16 p2, p4, 0x93

    const/16 v1, 0x92

    const/4 v8, 0x0

    if-eq p2, v1, :cond_4

    const/4 p2, 0x1

    goto :goto_3

    :cond_4
    move p2, v8

    :goto_3
    and-int/lit8 v1, p4, 0x1

    move-object v6, p3

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v1, p2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_5

    iget-object p2, p0, Llyiahf/vczjk/o51;->$items:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    move-object v2, p1

    check-cast v2, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;

    const p1, 0xc4b15ed

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, p0, Llyiahf/vczjk/o51;->$sortState$inlined:Llyiahf/vczjk/yp7;

    new-instance p1, Llyiahf/vczjk/mt;

    const/4 p2, 0x1

    invoke-direct {p1, v2, p2}, Llyiahf/vczjk/mt;-><init>(Ljava/lang/Object;I)V

    const p2, 0x62618cc2

    invoke-static {p2, p1, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    and-int/lit8 p1, p4, 0xe

    const p2, 0x180040

    or-int v7, p1, p2

    const/4 v4, 0x0

    const/4 v3, 0x0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/fu6;->OooO0Oo(Landroidx/compose/foundation/lazy/OooO00o;Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_5
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
