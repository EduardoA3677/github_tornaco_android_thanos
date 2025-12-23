.class public final Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;
.super Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0006\u00b2\u0006\u000c\u0010\u0005\u001a\u00020\u00048\nX\u008a\u0084\u0002"
    }
    d2 = {
        "Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "Llyiahf/vczjk/xu;",
        "state",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic OoooO0O:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 12

    move-object v9, p2

    check-cast v9, Llyiahf/vczjk/zf1;

    const p2, 0x27861b96

    invoke-virtual {v9, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x2

    const/4 v1, 0x4

    if-eqz p2, :cond_0

    move p2, v1

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    or-int/2addr p2, p1

    and-int/lit8 v2, p2, 0x3

    if-ne v2, v0, :cond_2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_2
    :goto_1
    const v0, 0x70b323c8

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v9}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v0

    if-eqz v0, :cond_9

    invoke-static {v0, v9}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v2

    const v3, 0x671a9c9b

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v3, v0, Llyiahf/vczjk/om3;

    if-eqz v3, :cond_3

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/om3;

    invoke-interface {v3}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v3

    goto :goto_2

    :cond_3
    sget-object v3, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_2
    const-class v4, Llyiahf/vczjk/dv;

    invoke-static {v4, v0, v2, v3, v9}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v2, 0x0

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v0, Llyiahf/vczjk/dv;

    iget-object v3, v0, Llyiahf/vczjk/dv;->OooO0Oo:Llyiahf/vczjk/gh7;

    invoke-static {v3, v9}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v3

    const v4, 0x6e3c21fe

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v5, :cond_4

    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v4

    const-string v6, "code"

    const/high16 v7, -0x80000000

    invoke-virtual {v4, v6, v7}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v6, Llyiahf/vczjk/ou;

    const/4 v7, 0x0

    invoke-direct {v6, v3, v7}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    const v7, 0x4e4aa2b

    invoke-static {v7, v6, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v6

    move v7, v2

    sget-object v2, Llyiahf/vczjk/m91;->OooO00o:Llyiahf/vczjk/a91;

    const v8, 0x4c5de2

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 p2, p2, 0xe

    if-eq p2, v1, :cond_5

    move p2, v7

    goto :goto_3

    :cond_5
    const/4 p2, 0x1

    :goto_3
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p2, :cond_6

    if-ne v1, v5, :cond_7

    :cond_6
    new-instance v1, Llyiahf/vczjk/k1;

    const/4 p2, 0x6

    invoke-direct {v1, p0, p2}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v9, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance p2, Llyiahf/vczjk/tu;

    invoke-direct {p2, v0, v4, v3, p0}, Llyiahf/vczjk/tu;-><init>(Llyiahf/vczjk/dv;ILlyiahf/vczjk/qs5;Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;)V

    const v0, -0x19ad500b

    invoke-static {v0, p2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    move-object v4, v1

    move-object v1, v6

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v0, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const v10, 0x60001b0

    const/16 v11, 0xe9

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_8

    new-instance v0, Llyiahf/vczjk/c4;

    const/4 v1, 0x3

    invoke-direct {v0, p1, v1, p0}, Llyiahf/vczjk/c4;-><init>(IILjava/lang/Object;)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOoo(Llyiahf/vczjk/xu;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 10

    move-object v7, p3

    check-cast v7, Llyiahf/vczjk/zf1;

    const v0, -0x51069598

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit8 v1, v0, 0x13

    const/16 v4, 0x12

    if-ne v1, v4, :cond_3

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    iget-object v3, p1, Llyiahf/vczjk/xu;->OooO0o0:Llyiahf/vczjk/nw;

    shl-int/lit8 v0, v0, 0x3

    and-int/lit16 v8, v0, 0x380

    iget-object v4, p1, Llyiahf/vczjk/xu;->OooO0o:Ljava/util/List;

    const/4 v6, 0x0

    const/16 v9, 0x8

    move-object v5, p2

    invoke-static/range {v3 .. v9}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_4

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/4 v5, 0x2

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method
