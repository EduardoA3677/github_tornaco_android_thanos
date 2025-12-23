.class public final Llyiahf/vczjk/kk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

.field final synthetic $content:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $pagerScope:Llyiahf/vczjk/pl6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ll1;Llyiahf/vczjk/df3;Llyiahf/vczjk/pl6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kk6;->$consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

    iput-object p2, p0, Llyiahf/vczjk/kk6;->$content:Llyiahf/vczjk/df3;

    iput-object p3, p0, Llyiahf/vczjk/kk6;->$pagerScope:Llyiahf/vczjk/pl6;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Landroidx/compose/foundation/lazy/OooO00o;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    move-result p4

    const-string v0, "$this$items"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, p4, 0xe

    if-nez v0, :cond_1

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    goto :goto_1

    :cond_1
    move v0, p4

    :goto_1
    and-int/lit8 p4, p4, 0x70

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
    or-int/2addr v0, p4

    :cond_3
    and-int/lit16 p4, v0, 0x2db

    const/16 v1, 0x92

    if-ne p4, v1, :cond_5

    move-object p4, p3

    check-cast p4, Llyiahf/vczjk/zf1;

    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_5
    :goto_3
    sget-object p4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v1, p0, Llyiahf/vczjk/kk6;->$consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

    const/4 v2, 0x0

    invoke-static {p4, v1, v2}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object p4

    invoke-static {p1, p4}, Landroidx/compose/foundation/lazy/OooO00o;->OooO00o(Landroidx/compose/foundation/lazy/OooO00o;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/4 p4, 0x3

    invoke-static {p1, v2, p4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo00(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ub0;I)Llyiahf/vczjk/kl5;

    move-result-object p1

    iget-object p4, p0, Llyiahf/vczjk/kk6;->$content:Llyiahf/vczjk/df3;

    iget-object v1, p0, Llyiahf/vczjk/kk6;->$pagerScope:Llyiahf/vczjk/pl6;

    sget-object v2, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v3, 0x0

    invoke-static {v2, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    move-object v3, p3

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {p3, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_6

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_6
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, p3, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, p3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_8

    :cond_7
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, p3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    and-int/lit8 p2, v0, 0x70

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-interface {p4, v1, p1, p3, p2}, Llyiahf/vczjk/df3;->OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-virtual {v3, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
