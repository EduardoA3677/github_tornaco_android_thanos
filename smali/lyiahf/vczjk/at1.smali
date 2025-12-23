.class public final Llyiahf/vczjk/at1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationSpec:Llyiahf/vczjk/p13;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p13;"
        }
    .end annotation
.end field

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $stateForContent:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $this_Crossfade:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/p13;Ljava/lang/Object;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/at1;->$this_Crossfade:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/at1;->$animationSpec:Llyiahf/vczjk/p13;

    iput-object p3, p0, Llyiahf/vczjk/at1;->$stateForContent:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/at1;->$content:Llyiahf/vczjk/bf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eq v0, v3, :cond_0

    move v0, v4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    and-int/2addr p2, v4

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_8

    iget-object v5, p0, Llyiahf/vczjk/at1;->$this_Crossfade:Llyiahf/vczjk/bz9;

    new-instance p1, Llyiahf/vczjk/zs1;

    iget-object p2, p0, Llyiahf/vczjk/at1;->$animationSpec:Llyiahf/vczjk/p13;

    invoke-direct {p1, p2}, Llyiahf/vczjk/zs1;-><init>(Llyiahf/vczjk/p13;)V

    iget-object p2, p0, Llyiahf/vczjk/at1;->$stateForContent:Ljava/lang/Object;

    sget-object v9, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    iget-object v0, v5, Llyiahf/vczjk/bz9;->OooO00o:Llyiahf/vczjk/tz9;

    invoke-virtual {v0}, Llyiahf/vczjk/tz9;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const v3, -0x1a25b2ec

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/4 v6, 0x0

    const/high16 v7, 0x3f800000    # 1.0f

    if-eqz v0, :cond_1

    move v0, v7

    goto :goto_1

    :cond_1
    move v0, v6

    :goto_1
    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    iget-object v8, v5, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v8, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_2

    move v6, v7

    :cond_2
    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v7

    invoke-virtual {v5}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object p2

    invoke-virtual {p1, p2, v10, v2}, Llyiahf/vczjk/zs1;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/p13;

    const/4 v11, 0x0

    move-object v6, v0

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/oz9;->OooO0OO(Llyiahf/vczjk/bz9;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/p13;Llyiahf/vczjk/m1a;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/uy9;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v0, :cond_3

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v0, :cond_4

    :cond_3
    new-instance v3, Llyiahf/vczjk/ys1;

    invoke-direct {v3, p1}, Llyiahf/vczjk/ys1;-><init>(Llyiahf/vczjk/uy9;)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {p2, v3}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/at1;->$content:Llyiahf/vczjk/bf3;

    iget-object v0, p0, Llyiahf/vczjk/at1;->$stateForContent:Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v3, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v10, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_5

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_5
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v10, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v10, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_7

    :cond_6
    invoke-static {v3, v10, v3, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, v10, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {p2, v0, v10, v2}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_8
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
