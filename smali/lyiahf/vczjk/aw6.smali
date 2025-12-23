.class public final Llyiahf/vczjk/aw6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $items:Ljava/util/List;

.field final synthetic $selectedPkgs$inlined:Ljava/util/List;

.field final synthetic $vm$inlined:Llyiahf/vczjk/gw6;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/gw6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aw6;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/aw6;->$selectedPkgs$inlined:Ljava/util/List;

    iput-object p3, p0, Llyiahf/vczjk/aw6;->$vm$inlined:Llyiahf/vczjk/gw6;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

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

    if-eqz p1, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/aw6;->$items:Ljava/util/List;

    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const p2, -0x109f2ed

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/aw6;->$selectedPkgs$inlined:Ljava/util/List;

    invoke-interface {p2, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result p2

    const p4, 0x4c5de2

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p4, p0, Llyiahf/vczjk/aw6;->$vm$inlined:Llyiahf/vczjk/gw6;

    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p4

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p4, :cond_5

    sget-object p4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p4, :cond_6

    :cond_5
    new-instance v0, Llyiahf/vczjk/f5;

    iget-object p4, p0, Llyiahf/vczjk/aw6;->$vm$inlined:Llyiahf/vczjk/gw6;

    const/16 v1, 0x16

    invoke-direct {v0, p4, v1}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v0, Llyiahf/vczjk/ze3;

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p1, p2, v0, p3, v2}, Llyiahf/vczjk/ok6;->OooO0OO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_7
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
