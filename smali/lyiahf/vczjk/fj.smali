.class public final Llyiahf/vczjk/fj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


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


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tw8;Ljava/lang/Object;Llyiahf/vczjk/uj;Llyiahf/vczjk/df3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fj;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iput-object p2, p0, Llyiahf/vczjk/fj;->$stateForContent:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/fj;->$rootScope:Llyiahf/vczjk/uj;

    iput-object p4, p0, Llyiahf/vczjk/fj;->$content:Llyiahf/vczjk/df3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/vk;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    and-int/lit8 v0, p3, 0x6

    if-nez v0, :cond_2

    and-int/lit8 v0, p3, 0x8

    if-nez v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    goto :goto_0

    :cond_0
    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    :goto_0
    if-eqz v0, :cond_1

    const/4 v0, 0x4

    goto :goto_1

    :cond_1
    const/4 v0, 0x2

    :goto_1
    or-int/2addr p3, v0

    :cond_2
    and-int/lit8 v0, p3, 0x13

    const/4 v1, 0x1

    const/16 v2, 0x12

    const/4 v3, 0x0

    if-eq v0, v2, :cond_3

    move v0, v1

    goto :goto_2

    :cond_3
    move v0, v3

    :goto_2
    and-int/2addr p3, v1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p3, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p3

    if-eqz p3, :cond_7

    iget-object p3, p0, Llyiahf/vczjk/fj;->$currentlyVisible:Llyiahf/vczjk/tw8;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    iget-object v0, p0, Llyiahf/vczjk/fj;->$stateForContent:Ljava/lang/Object;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v0, p0, Llyiahf/vczjk/fj;->$rootScope:Llyiahf/vczjk/uj;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v0, p0, Llyiahf/vczjk/fj;->$currentlyVisible:Llyiahf/vczjk/tw8;

    iget-object v1, p0, Llyiahf/vczjk/fj;->$stateForContent:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/fj;->$rootScope:Llyiahf/vczjk/uj;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p3, :cond_4

    if-ne v4, v5, :cond_5

    :cond_4
    new-instance v4, Llyiahf/vczjk/ej;

    invoke-direct {v4, v0, v1, v2}, Llyiahf/vczjk/ej;-><init>(Llyiahf/vczjk/tw8;Ljava/lang/Object;Llyiahf/vczjk/uj;)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-static {p1, v4, p2}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    iget-object p3, p0, Llyiahf/vczjk/fj;->$rootScope:Llyiahf/vczjk/uj;

    iget-object p3, p3, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    iget-object v0, p0, Llyiahf/vczjk/fj;->$stateForContent:Ljava/lang/Object;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.AnimatedVisibilityScopeImpl"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/wk;

    iget-object p1, p1, Llyiahf/vczjk/wk;->OooO00o:Llyiahf/vczjk/qs5;

    invoke-virtual {p3, v0, p1}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v5, :cond_6

    new-instance p1, Llyiahf/vczjk/kj;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast p1, Llyiahf/vczjk/kj;

    iget-object p3, p0, Llyiahf/vczjk/fj;->$content:Llyiahf/vczjk/df3;

    iget-object v0, p0, Llyiahf/vczjk/fj;->$stateForContent:Ljava/lang/Object;

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {p3, p1, v0, p2, v1}, Llyiahf/vczjk/df3;->OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_3

    :cond_7
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
