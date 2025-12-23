.class public final Landroidx/compose/foundation/selection/OooO0OO;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $enabled$inlined:Z

.field final synthetic $indication:Llyiahf/vczjk/lx3;

.field final synthetic $onClick$inlined:Llyiahf/vczjk/le3;

.field final synthetic $role$inlined:Llyiahf/vczjk/gu7;

.field final synthetic $state$inlined:Llyiahf/vczjk/gt9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/du7;Llyiahf/vczjk/gu7;Llyiahf/vczjk/gt9;Z)V
    .locals 0

    iput-object p2, p0, Landroidx/compose/foundation/selection/OooO0OO;->$indication:Llyiahf/vczjk/lx3;

    iput-object p4, p0, Landroidx/compose/foundation/selection/OooO0OO;->$state$inlined:Llyiahf/vczjk/gt9;

    iput-boolean p5, p0, Landroidx/compose/foundation/selection/OooO0OO;->$enabled$inlined:Z

    iput-object p3, p0, Landroidx/compose/foundation/selection/OooO0OO;->$role$inlined:Llyiahf/vczjk/gu7;

    iput-object p1, p0, Landroidx/compose/foundation/selection/OooO0OO;->$onClick$inlined:Llyiahf/vczjk/le3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p1, -0x5af0b3b9

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p1, p3, :cond_0

    invoke-static {p2}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object p1

    :cond_0
    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/rr5;

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object p3, p0, Landroidx/compose/foundation/selection/OooO0OO;->$indication:Llyiahf/vczjk/lx3;

    invoke-static {p1, v2, p3}, Landroidx/compose/foundation/OooO0o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    new-instance v0, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    iget-object v1, p0, Landroidx/compose/foundation/selection/OooO0OO;->$state$inlined:Llyiahf/vczjk/gt9;

    iget-boolean v4, p0, Landroidx/compose/foundation/selection/OooO0OO;->$enabled$inlined:Z

    iget-object v5, p0, Landroidx/compose/foundation/selection/OooO0OO;->$role$inlined:Llyiahf/vczjk/gu7;

    iget-object v6, p0, Landroidx/compose/foundation/selection/OooO0OO;->$onClick$inlined:Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Llyiahf/vczjk/gt9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
