.class public final Landroidx/compose/foundation/OooO0OO;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $enabled$inlined:Z

.field final synthetic $hapticFeedbackEnabled$inlined:Z

.field final synthetic $indication:Llyiahf/vczjk/lx3;

.field final synthetic $onClick$inlined:Llyiahf/vczjk/le3;

.field final synthetic $onClickLabel$inlined:Ljava/lang/String;

.field final synthetic $onDoubleClick$inlined:Llyiahf/vczjk/le3;

.field final synthetic $onLongClick$inlined:Llyiahf/vczjk/le3;

.field final synthetic $onLongClickLabel$inlined:Ljava/lang/String;

.field final synthetic $role$inlined:Llyiahf/vczjk/gu7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Z)V
    .locals 0

    iput-object p1, p0, Landroidx/compose/foundation/OooO0OO;->$indication:Llyiahf/vczjk/lx3;

    iput-boolean p2, p0, Landroidx/compose/foundation/OooO0OO;->$enabled$inlined:Z

    iput-object p3, p0, Landroidx/compose/foundation/OooO0OO;->$onClickLabel$inlined:Ljava/lang/String;

    iput-object p4, p0, Landroidx/compose/foundation/OooO0OO;->$role$inlined:Llyiahf/vczjk/gu7;

    iput-object p5, p0, Landroidx/compose/foundation/OooO0OO;->$onClick$inlined:Llyiahf/vczjk/le3;

    iput-object p6, p0, Landroidx/compose/foundation/OooO0OO;->$onLongClickLabel$inlined:Ljava/lang/String;

    iput-object p7, p0, Landroidx/compose/foundation/OooO0OO;->$onLongClick$inlined:Llyiahf/vczjk/le3;

    iput-object p8, p0, Landroidx/compose/foundation/OooO0OO;->$onDoubleClick$inlined:Llyiahf/vczjk/le3;

    iput-boolean p9, p0, Landroidx/compose/foundation/OooO0OO;->$hapticFeedbackEnabled$inlined:Z

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

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
    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/rr5;

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object p3, p0, Landroidx/compose/foundation/OooO0OO;->$indication:Llyiahf/vczjk/lx3;

    invoke-static {p1, v7, p3}, Landroidx/compose/foundation/OooO0o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    new-instance v0, Landroidx/compose/foundation/CombinedClickableElement;

    iget-boolean v9, p0, Landroidx/compose/foundation/OooO0OO;->$enabled$inlined:Z

    iget-object v1, p0, Landroidx/compose/foundation/OooO0OO;->$onClickLabel$inlined:Ljava/lang/String;

    iget-object v8, p0, Landroidx/compose/foundation/OooO0OO;->$role$inlined:Llyiahf/vczjk/gu7;

    iget-object v3, p0, Landroidx/compose/foundation/OooO0OO;->$onClick$inlined:Llyiahf/vczjk/le3;

    iget-object v2, p0, Landroidx/compose/foundation/OooO0OO;->$onLongClickLabel$inlined:Ljava/lang/String;

    iget-object v4, p0, Landroidx/compose/foundation/OooO0OO;->$onLongClick$inlined:Llyiahf/vczjk/le3;

    iget-object v5, p0, Landroidx/compose/foundation/OooO0OO;->$onDoubleClick$inlined:Llyiahf/vczjk/le3;

    iget-boolean v10, p0, Landroidx/compose/foundation/OooO0OO;->$hapticFeedbackEnabled$inlined:Z

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v10}, Landroidx/compose/foundation/CombinedClickableElement;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/px3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/gu7;ZZ)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/4 p3, 0x0

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
