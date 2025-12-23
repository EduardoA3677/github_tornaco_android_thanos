.class public final Llyiahf/vczjk/jsa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kg1;
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/sg1;

.field public final OooOOO0:Llyiahf/vczjk/xa;

.field public OooOOOO:Z

.field public OooOOOo:Llyiahf/vczjk/ky4;

.field public OooOOo0:Llyiahf/vczjk/ze3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/sg1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    iput-object p2, p0, Llyiahf/vczjk/jsa;->OooOOO:Llyiahf/vczjk/sg1;

    sget-object p1, Llyiahf/vczjk/od1;->OooO00o:Llyiahf/vczjk/a91;

    iput-object p1, p0, Llyiahf/vczjk/jsa;->OooOOo0:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/jsa;->OooOOOO:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/jsa;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getView()Landroid/view/View;

    move-result-object v0

    sget v1, Landroidx/compose/ui/R$id;->wrapped_composition_tag:I

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/jsa;->OooOOOo:Llyiahf/vczjk/ky4;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jsa;->OooOOO:Llyiahf/vczjk/sg1;

    invoke-virtual {v0}, Llyiahf/vczjk/sg1;->OooOO0o()V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/ze3;)V
    .locals 1

    new-instance v0, Llyiahf/vczjk/isa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/isa;-><init>(Llyiahf/vczjk/jsa;Llyiahf/vczjk/ze3;)V

    iget-object p1, p0, Llyiahf/vczjk/jsa;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/xa;->setOnViewTreeOwnersAvailable(Llyiahf/vczjk/oe3;)V

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 0

    sget-object p1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/jsa;->OooO00o()V

    return-void

    :cond_0
    sget-object p1, Llyiahf/vczjk/iy4;->ON_CREATE:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/jsa;->OooOOOO:Z

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/jsa;->OooOOo0:Llyiahf/vczjk/ze3;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/jsa;->OooO0O0(Llyiahf/vczjk/ze3;)V

    :cond_1
    return-void
.end method
