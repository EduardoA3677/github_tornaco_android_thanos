.class public final Llyiahf/vczjk/hsa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/jsa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/ze3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iput-object p2, p0, Llyiahf/vczjk/hsa;->$content:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eq v0, v1, :cond_0

    move v0, v3

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    and-int/2addr p2, v3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_f

    iget-object p2, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iget-object p2, p2, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    sget v0, Landroidx/compose/ui/R$id;->inspection_slot_table_set:I

    invoke-virtual {p2, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object p2

    instance-of v0, p2, Ljava/util/Set;

    if-eqz v0, :cond_2

    instance-of v0, p2, Llyiahf/vczjk/cg4;

    if-eqz v0, :cond_1

    instance-of v0, p2, Llyiahf/vczjk/sg4;

    if-eqz v0, :cond_2

    :cond_1
    move v2, v3

    :cond_2
    const/4 v0, 0x0

    if-eqz v2, :cond_3

    check-cast p2, Ljava/util/Set;

    goto :goto_1

    :cond_3
    move-object p2, v0

    :goto_1
    if-nez p2, :cond_8

    iget-object p2, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iget-object p2, p2, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p2}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p2

    instance-of v1, p2, Landroid/view/View;

    if-eqz v1, :cond_4

    check-cast p2, Landroid/view/View;

    goto :goto_2

    :cond_4
    move-object p2, v0

    :goto_2
    if-eqz p2, :cond_5

    sget v1, Landroidx/compose/ui/R$id;->inspection_slot_table_set:I

    invoke-virtual {p2, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object p2

    goto :goto_3

    :cond_5
    move-object p2, v0

    :goto_3
    instance-of v1, p2, Ljava/util/Set;

    if-eqz v1, :cond_7

    instance-of v1, p2, Llyiahf/vczjk/cg4;

    if-eqz v1, :cond_6

    instance-of v1, p2, Llyiahf/vczjk/sg4;

    if-eqz v1, :cond_7

    :cond_6
    check-cast p2, Ljava/util/Set;

    goto :goto_4

    :cond_7
    move-object p2, v0

    :cond_8
    :goto_4
    if-eqz p2, :cond_a

    iget-object v1, p1, Llyiahf/vczjk/zf1;->OoooO00:Llyiahf/vczjk/og1;

    if-nez v1, :cond_9

    new-instance v1, Llyiahf/vczjk/og1;

    iget-object v2, p1, Llyiahf/vczjk/zf1;->OooO0oO:Llyiahf/vczjk/sg1;

    invoke-direct {v1, v2}, Llyiahf/vczjk/og1;-><init>(Llyiahf/vczjk/sg1;)V

    iput-object v1, p1, Llyiahf/vczjk/zf1;->OoooO00:Llyiahf/vczjk/og1;

    :cond_9
    invoke-interface {p2, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    iput-boolean v3, p1, Llyiahf/vczjk/zf1;->OooOOOo:Z

    iput-boolean v3, p1, Llyiahf/vczjk/zf1;->OooOoo0:Z

    iget-object v1, p1, Llyiahf/vczjk/zf1;->OooO0OO:Llyiahf/vczjk/js8;

    invoke-virtual {v1}, Llyiahf/vczjk/js8;->OooOO0()V

    iget-object v1, p1, Llyiahf/vczjk/zf1;->Oooo00O:Llyiahf/vczjk/js8;

    invoke-virtual {v1}, Llyiahf/vczjk/js8;->OooOO0()V

    iget-object v1, p1, Llyiahf/vczjk/zf1;->Oooo00o:Llyiahf/vczjk/os8;

    iget-object v2, v1, Llyiahf/vczjk/os8;->OooO00o:Llyiahf/vczjk/js8;

    iget-object v3, v2, Llyiahf/vczjk/js8;->OooOo0O:Ljava/util/HashMap;

    iput-object v3, v1, Llyiahf/vczjk/os8;->OooO0o0:Ljava/util/HashMap;

    iget-object v2, v2, Llyiahf/vczjk/js8;->OooOo0o:Llyiahf/vczjk/or5;

    iput-object v2, v1, Llyiahf/vczjk/os8;->OooO0o:Llyiahf/vczjk/or5;

    :cond_a
    iget-object v1, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iget-object v2, v1, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v3, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v1, :cond_b

    if-ne v4, v5, :cond_c

    :cond_b
    new-instance v4, Llyiahf/vczjk/esa;

    invoke-direct {v4, v3, v0}, Llyiahf/vczjk/esa;-><init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static {v2, p1, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v1, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iget-object v2, v1, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v3, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_d

    if-ne v4, v5, :cond_e

    :cond_d
    new-instance v4, Llyiahf/vczjk/fsa;

    invoke-direct {v4, v3, v0}, Llyiahf/vczjk/fsa;-><init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static {v2, p1, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/k14;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/gsa;

    iget-object v1, p0, Llyiahf/vczjk/hsa;->this$0:Llyiahf/vczjk/jsa;

    iget-object v2, p0, Llyiahf/vczjk/hsa;->$content:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gsa;-><init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/ze3;)V

    const v1, -0x4722c3de

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_5

    :cond_f
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
