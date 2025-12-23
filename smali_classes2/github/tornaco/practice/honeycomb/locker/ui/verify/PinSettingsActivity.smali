.class public final Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;
.super Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0006\u00b2\u0006\u000c\u0010\u0005\u001a\u00020\u00048\nX\u008a\u0084\u0002"
    }
    d2 = {
        "Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "Llyiahf/vczjk/su6;",
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

    invoke-direct {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 13

    move-object v9, p2

    check-cast v9, Llyiahf/vczjk/zf1;

    const p2, 0x7949022e

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

    move-object p2, p0

    goto/16 :goto_4

    :cond_2
    :goto_1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    move-object v4, v0

    check-cast v4, Landroid/content/Context;

    const v0, 0x70b323c8

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v9}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v0

    if-eqz v0, :cond_8

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
    const-class v5, Llyiahf/vczjk/pu6;

    invoke-static {v5, v0, v2, v3, v9}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v2, 0x0

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/pu6;

    iget-object v0, v3, Llyiahf/vczjk/pu6;->OooO0oO:Llyiahf/vczjk/gh7;

    invoke-static {v0, v9}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v6

    move v0, v1

    sget-object v1, Llyiahf/vczjk/mb1;->OooO00o:Llyiahf/vczjk/a91;

    sget-object v8, Llyiahf/vczjk/mb1;->OooO0O0:Llyiahf/vczjk/a91;

    const v5, 0x4c5de2

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 p2, p2, 0xe

    if-eq p2, v0, :cond_4

    move p2, v2

    goto :goto_3

    :cond_4
    const/4 p2, 0x1

    :goto_3
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_5

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_6

    :cond_5
    new-instance v0, Llyiahf/vczjk/fz3;

    const/16 p2, 0x17

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v0, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/a6;

    const/16 v7, 0x8

    move-object v5, p0

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object p2, v5

    const v3, 0x53fa7b6f

    invoke-static {v3, v2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v4, v0

    const/4 v0, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const v10, 0x60001b0

    const/16 v11, 0xe9

    move-object v12, v8

    move-object v8, v2

    move-object v2, v12

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_7

    new-instance v1, Llyiahf/vczjk/sj5;

    const/16 v2, 0x8

    invoke-direct {v1, p1, v2, p0}, Llyiahf/vczjk/sj5;-><init>(IILjava/lang/Object;)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void

    :cond_8
    move-object p2, p0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
