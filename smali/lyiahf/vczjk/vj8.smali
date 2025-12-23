.class public final Llyiahf/vczjk/vj8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dq6;
.implements Llyiahf/vczjk/z70;
.implements Llyiahf/vczjk/hj4;


# instance fields
.field public final OooO00o:Landroid/graphics/Path;

.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Z

.field public final OooO0Oo:Llyiahf/vczjk/v85;

.field public OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/ek8;

.field public final OooO0oO:Llyiahf/vczjk/eh1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/ok8;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/vj8;->OooO00o:Landroid/graphics/Path;

    new-instance v0, Llyiahf/vczjk/eh1;

    invoke-direct {v0}, Llyiahf/vczjk/eh1;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/vj8;->OooO0oO:Llyiahf/vczjk/eh1;

    iget-object v0, p3, Llyiahf/vczjk/ok8;->OooO00o:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/vj8;->OooO0O0:Ljava/lang/String;

    iget-boolean v0, p3, Llyiahf/vczjk/ok8;->OooO0Oo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/vj8;->OooO0OO:Z

    iput-object p1, p0, Llyiahf/vczjk/vj8;->OooO0Oo:Llyiahf/vczjk/v85;

    new-instance p1, Llyiahf/vczjk/ek8;

    iget-object p3, p3, Llyiahf/vczjk/ok8;->OooO0OO:Llyiahf/vczjk/hi;

    iget-object p3, p3, Llyiahf/vczjk/l21;->OooOOO:Ljava/lang/Object;

    check-cast p3, Ljava/util/List;

    invoke-direct {p1, p3}, Llyiahf/vczjk/ek8;-><init>(Ljava/util/List;)V

    iput-object p1, p0, Llyiahf/vczjk/vj8;->OooO0o0:Llyiahf/vczjk/ek8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/vj8;->OooO0o:Z

    iget-object v0, p0, Llyiahf/vczjk/vj8;->OooO0Oo:Llyiahf/vczjk/v85;

    invoke-virtual {v0}, Llyiahf/vczjk/v85;->invalidateSelf()V

    return-void
.end method

.method public final OooO0O0(Ljava/util/List;Ljava/util/List;)V
    .locals 5

    const/4 p2, 0x0

    const/4 v0, 0x0

    :goto_0
    move-object v1, p1

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    if-ge v0, v2, :cond_3

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fm1;

    instance-of v2, v1, Llyiahf/vczjk/c1a;

    if-eqz v2, :cond_0

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/c1a;

    iget v3, v2, Llyiahf/vczjk/c1a;->OooO0OO:I

    const/4 v4, 0x1

    if-ne v3, v4, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/vj8;->OooO0oO:Llyiahf/vczjk/eh1;

    iget-object v1, v1, Llyiahf/vczjk/eh1;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v2, p0}, Llyiahf/vczjk/c1a;->OooO0OO(Llyiahf/vczjk/z70;)V

    goto :goto_1

    :cond_0
    instance-of v2, v1, Llyiahf/vczjk/xv7;

    if-eqz v2, :cond_2

    if-nez p2, :cond_1

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    :cond_1
    check-cast v1, Llyiahf/vczjk/xv7;

    iget-object v2, v1, Llyiahf/vczjk/xv7;->OooO0O0:Llyiahf/vczjk/d80;

    invoke-virtual {v2, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-interface {p2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_2
    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/vj8;->OooO0o0:Llyiahf/vczjk/ek8;

    iput-object p2, p1, Llyiahf/vczjk/ek8;->OooOOO0:Ljava/util/ArrayList;

    return-void
.end method

.method public final OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/c95;->Oooo0OO:Landroid/graphics/Path;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/vj8;->OooO0o0:Llyiahf/vczjk/ek8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/d80;->OooOO0(Llyiahf/vczjk/n62;)V

    :cond_0
    return-void
.end method

.method public final OooO0oO()Landroid/graphics/Path;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/vj8;->OooO0o:Z

    iget-object v1, p0, Llyiahf/vczjk/vj8;->OooO00o:Landroid/graphics/Path;

    iget-object v2, p0, Llyiahf/vczjk/vj8;->OooO0o0:Llyiahf/vczjk/ek8;

    if-eqz v0, :cond_1

    iget-object v0, v2, Llyiahf/vczjk/d80;->OooO0o0:Llyiahf/vczjk/n62;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    return-object v1

    :cond_1
    :goto_0
    invoke-virtual {v1}, Landroid/graphics/Path;->reset()V

    iget-boolean v0, p0, Llyiahf/vczjk/vj8;->OooO0OO:Z

    const/4 v3, 0x1

    if-eqz v0, :cond_2

    iput-boolean v3, p0, Llyiahf/vczjk/vj8;->OooO0o:Z

    return-object v1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/graphics/Path;

    if-nez v0, :cond_3

    return-object v1

    :cond_3
    invoke-virtual {v1, v0}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    sget-object v0, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    invoke-virtual {v1, v0}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    iget-object v0, p0, Llyiahf/vczjk/vj8;->OooO0oO:Llyiahf/vczjk/eh1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/eh1;->OooO0OO(Landroid/graphics/Path;)V

    iput-boolean v3, p0, Llyiahf/vczjk/vj8;->OooO0o:Z

    return-object v1
.end method

.method public final OooO0oo(Llyiahf/vczjk/fj4;ILjava/util/ArrayList;Llyiahf/vczjk/fj4;)V
    .locals 0

    invoke-static {p1, p2, p3, p4, p0}, Llyiahf/vczjk/pj5;->OooO0oO(Llyiahf/vczjk/fj4;ILjava/util/ArrayList;Llyiahf/vczjk/fj4;Llyiahf/vczjk/hj4;)V

    return-void
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vj8;->OooO0O0:Ljava/lang/String;

    return-object v0
.end method
