.class public final Llyiahf/vczjk/gj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $currentlyVisible:Llyiahf/vczjk/tw8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tw8;"
        }
    .end annotation
.end field

.field final synthetic $rootScope:Llyiahf/vczjk/uj;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/uj;"
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

.field final synthetic $this_AnimatedContent:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $transitionSpec:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/uj;Llyiahf/vczjk/tw8;Llyiahf/vczjk/df3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/gj;->$transitionSpec:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/gj;->$rootScope:Llyiahf/vczjk/uj;

    iput-object p5, p0, Llyiahf/vczjk/gj;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iput-object p6, p0, Llyiahf/vczjk/gj;->$content:Llyiahf/vczjk/df3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_c

    iget-object p1, p0, Llyiahf/vczjk/gj;->$transitionSpec:Llyiahf/vczjk/oe3;

    iget-object p2, p0, Llyiahf/vczjk/gj;->$rootScope:Llyiahf/vczjk/uj;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v1, :cond_1

    invoke-interface {p1, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/fn1;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v0, Llyiahf/vczjk/fn1;

    iget-object p1, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    invoke-virtual {p1}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iget-object v2, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/gj;->$transitionSpec:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/gj;->$rootScope:Llyiahf/vczjk/uj;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez p1, :cond_2

    if-ne v5, v1, :cond_4

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/bz9;->OooO0o()Llyiahf/vczjk/sy9;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/sy9;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/ct2;->OooO00o:Llyiahf/vczjk/dt2;

    :goto_1
    move-object v5, p1

    goto :goto_2

    :cond_3
    invoke-interface {v3, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fn1;

    iget-object p1, p1, Llyiahf/vczjk/fn1;->OooO0O0:Llyiahf/vczjk/ct2;

    goto :goto_1

    :goto_2
    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v5, Llyiahf/vczjk/ct2;

    iget-object p1, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    iget-object p2, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_5

    new-instance v2, Llyiahf/vczjk/lj;

    iget-object p2, p2, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    invoke-direct {v2, p1}, Llyiahf/vczjk/lj;-><init>(Z)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v2, Llyiahf/vczjk/lj;

    iget-object v4, v0, Llyiahf/vczjk/fn1;->OooO00o:Llyiahf/vczjk/ep2;

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez p2, :cond_6

    if-ne v3, v1, :cond_7

    :cond_6
    new-instance v3, Llyiahf/vczjk/bj;

    invoke-direct {v3, v0}, Llyiahf/vczjk/bj;-><init>(Llyiahf/vczjk/fn1;)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v3, Llyiahf/vczjk/bf3;

    invoke-static {p1, v3}, Landroidx/compose/ui/layout/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    iget-object v0, v2, Llyiahf/vczjk/lj;->OooOOO0:Llyiahf/vczjk/qs5;

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    move-object p1, v1

    iget-object v1, p0, Llyiahf/vczjk/gj;->$this_AnimatedContent:Llyiahf/vczjk/bz9;

    iget-object p2, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez p2, :cond_8

    if-ne v2, p1, :cond_9

    :cond_8
    new-instance v2, Llyiahf/vczjk/cj;

    invoke-direct {v2, v0}, Llyiahf/vczjk/cj;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_a

    if-ne v0, p1, :cond_b

    :cond_a
    new-instance v0, Llyiahf/vczjk/dj;

    invoke-direct {v0, v5}, Llyiahf/vczjk/dj;-><init>(Llyiahf/vczjk/ct2;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/ze3;

    new-instance p1, Llyiahf/vczjk/fj;

    iget-object p2, p0, Llyiahf/vczjk/gj;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iget-object v0, p0, Llyiahf/vczjk/gj;->$stateForContent:Ljava/lang/Object;

    iget-object v7, p0, Llyiahf/vczjk/gj;->$rootScope:Llyiahf/vczjk/uj;

    iget-object v9, p0, Llyiahf/vczjk/gj;->$content:Llyiahf/vczjk/df3;

    invoke-direct {p1, p2, v0, v7, v9}, Llyiahf/vczjk/fj;-><init>(Llyiahf/vczjk/tw8;Ljava/lang/Object;Llyiahf/vczjk/uj;Llyiahf/vczjk/df3;)V

    const p2, -0x24ba65ea

    invoke-static {p2, p1, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const/16 v10, 0x40

    const/high16 v9, 0xc00000

    invoke-static/range {v1 .. v10}, Landroidx/compose/animation/OooO0O0;->OooO00o(Llyiahf/vczjk/bz9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    goto :goto_3

    :cond_c
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
