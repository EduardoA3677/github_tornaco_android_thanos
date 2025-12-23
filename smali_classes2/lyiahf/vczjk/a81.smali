.class public final Llyiahf/vczjk/a81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/b71;

.field public final synthetic OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Llyiahf/vczjk/t81;

.field public final synthetic OooOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/b71;ZLlyiahf/vczjk/t81;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a81;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    iput-object p2, p0, Llyiahf/vczjk/a81;->OooOOO:Llyiahf/vczjk/b71;

    iput-boolean p3, p0, Llyiahf/vczjk/a81;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/a81;->OooOOOo:Llyiahf/vczjk/t81;

    iput-object p5, p0, Llyiahf/vczjk/a81;->OooOOo0:Llyiahf/vczjk/qs5;

    iput-object p6, p0, Llyiahf/vczjk/a81;->OooOOo:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p2

    const-string p4, "$this$stickyHeader"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 p1, p2, 0x81

    const/16 p2, 0x80

    if-ne p1, p2, :cond_1

    move-object p1, p3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_1

    :cond_1
    :goto_0
    iget-boolean p1, p0, Llyiahf/vczjk/a81;->OooOOOO:Z

    xor-int/lit8 v2, p1, 0x1

    iget-object p1, p0, Llyiahf/vczjk/a81;->OooOOo0:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Set;

    iget-object v1, p0, Llyiahf/vczjk/a81;->OooOOO:Llyiahf/vczjk/b71;

    iget-object p2, v1, Llyiahf/vczjk/b71;->OooO0OO:Ljava/lang/String;

    invoke-interface {p1, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 v3, p1, 0x1

    move-object v8, p3

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, -0x615d173a

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/a81;->OooOOOo:Llyiahf/vczjk/t81;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    or-int/2addr p2, p3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p3

    sget-object p4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p2, :cond_2

    if-ne p3, p4, :cond_3

    :cond_2
    new-instance p3, Llyiahf/vczjk/o0OO000o;

    const/16 p2, 0xa

    invoke-direct {p3, p2, p1, v1}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v8, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v4, p3

    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 p2, 0x0

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget p3, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    iget-object p3, p0, Llyiahf/vczjk/a81;->OooOOo:Llyiahf/vczjk/qs5;

    invoke-interface {p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cr5;

    iget-boolean v5, v0, Llyiahf/vczjk/cr5;->OooO00o:Z

    invoke-interface {p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/cr5;

    iget-object p3, p3, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    iget-object v0, v1, Llyiahf/vczjk/b71;->OooO0O0:Ljava/util/List;

    invoke-interface {p3, v0}, Ljava/util/Set;->containsAll(Ljava/util/Collection;)Z

    move-result v6

    const p3, 0x4c5de2

    invoke-virtual {v8, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_4

    if-ne v0, p4, :cond_5

    :cond_4
    new-instance v0, Llyiahf/vczjk/c4;

    const/16 p3, 0x9

    invoke-direct {v0, p1, p3}, Llyiahf/vczjk/c4;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget p1, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;->Oooo0oO:I

    const/high16 v9, 0x1000000

    iget-object v0, p0, Llyiahf/vczjk/a81;->OooOOO0:Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-virtual/range {v0 .. v9}, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OooOooO(Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
