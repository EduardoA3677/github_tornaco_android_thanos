.class public final Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;
.super Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0002\u0008\u0007\u0018\u00002\u00020\u0001:\u0001\u0004B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0016\u00b2\u0006\u000c\u0010\u0006\u001a\u00020\u00058\nX\u008a\u0084\u0002\u00b2\u0006\u000c\u0010\u0008\u001a\u00020\u00078\nX\u008a\u0084\u0002\u00b2\u0006\u000c\u0010\n\u001a\u00020\t8\nX\u008a\u0084\u0002\u00b2\u0006\u0018\u0010\u000e\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\r0\u000c0\u000b8\nX\u008a\u0084\u0002\u00b2\u0006\u0012\u0010\u0011\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u000f8\nX\u008a\u0084\u0002\u00b2\u0006\u000e\u0010\u0013\u001a\u00020\u00128\n@\nX\u008a\u008e\u0002\u00b2\u0006\u000c\u0010\u0015\u001a\u00020\u00148\nX\u008a\u0084\u0002"
    }
    d2 = {
        "Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "lyiahf/vczjk/qqa",
        "Llyiahf/vczjk/cr5;",
        "selectState",
        "Llyiahf/vczjk/ka0;",
        "batchOpState",
        "Llyiahf/vczjk/yia;",
        "viewType",
        "Llyiahf/vczjk/r7a;",
        "",
        "Llyiahf/vczjk/b71;",
        "components",
        "",
        "",
        "collapsedGroups",
        "",
        "isChecked",
        "",
        "rotate",
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

    invoke-direct {p0}, Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 21

    move-object/from16 v4, p0

    move/from16 v6, p1

    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/zf1;

    const v0, 0x4933ec08    # 736960.5f

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x4

    const/4 v2, 0x2

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    or-int/2addr v0, v6

    and-int/lit8 v3, v0, 0x3

    if-ne v3, v2, :cond_2

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v16, v7

    goto/16 :goto_9

    :cond_2
    :goto_1
    const v3, 0x6e3c21fe

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v8, :cond_5

    invoke-virtual {v4}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v5

    const-string v9, "type"

    invoke-virtual {v5, v9}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    if-nez v5, :cond_3

    const-string v5, ""

    :cond_3
    invoke-static {v5}, Llyiahf/vczjk/r71;->valueOf(Ljava/lang/String;)Llyiahf/vczjk/r71;

    move-result-object v5

    if-eqz v5, :cond_4

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_2

    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Type is null."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_5
    :goto_2
    check-cast v5, Llyiahf/vczjk/r71;

    const/4 v9, 0x0

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v10

    const v11, 0x671a9c9b

    const-string v12, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    const v13, 0x70b323c8

    const/4 v14, 0x1

    if-eqz v10, :cond_f

    if-eq v10, v14, :cond_c

    if-eq v10, v2, :cond_9

    const/4 v2, 0x3

    if-ne v10, v2, :cond_8

    const v2, -0x4ebec022

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v7}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_7

    invoke-static {v2, v7}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v10

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v11, v2, Llyiahf/vczjk/om3;

    if-eqz v11, :cond_6

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/om3;

    invoke-interface {v11}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v11

    goto :goto_3

    :cond_6
    sget-object v11, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_3
    const-class v12, Llyiahf/vczjk/me7;

    invoke-static {v12, v2, v10, v11, v7}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v2

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v2, Llyiahf/vczjk/me7;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_7

    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8
    const v0, -0x3416d177    # -3.0563602E7f

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_9
    const v2, -0x4ec01d01

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v7}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_b

    invoke-static {v2, v7}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v10

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v11, v2, Llyiahf/vczjk/om3;

    if-eqz v11, :cond_a

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/om3;

    invoke-interface {v11}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v11

    goto :goto_4

    :cond_a
    sget-object v11, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_4
    const-class v12, Llyiahf/vczjk/dh8;

    invoke-static {v12, v2, v10, v11, v7}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v2

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v2, Llyiahf/vczjk/dh8;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_7

    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_c
    const v2, -0x4ec179a2

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v7}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_e

    invoke-static {v2, v7}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v10

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v11, v2, Llyiahf/vczjk/om3;

    if-eqz v11, :cond_d

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/om3;

    invoke-interface {v11}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v11

    goto :goto_5

    :cond_d
    sget-object v11, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_5
    const-class v12, Llyiahf/vczjk/wi7;

    invoke-static {v12, v2, v10, v11, v7}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v2

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v2, Llyiahf/vczjk/wi7;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_7

    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_f
    const v2, -0x4ec2de03

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v7}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_1d

    invoke-static {v2, v7}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v10

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v11, v2, Llyiahf/vczjk/om3;

    if-eqz v11, :cond_10

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/om3;

    invoke-interface {v11}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v11

    goto :goto_6

    :cond_10
    sget-object v11, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_6
    const-class v12, Llyiahf/vczjk/oOo00o0o;

    invoke-static {v12, v2, v10, v11, v7}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v2

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v2, Llyiahf/vczjk/oOo00o0o;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_7
    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v8, :cond_12

    invoke-virtual {v4}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v3

    const-string v10, "app"

    invoke-virtual {v3, v10}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v3

    if-eqz v3, :cond_11

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_8

    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "App info is null."

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_12
    :goto_8
    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v10, -0x615d173a

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    const/4 v13, 0x0

    if-nez v11, :cond_13

    if-ne v12, v8, :cond_14

    :cond_13
    new-instance v12, Llyiahf/vczjk/s71;

    invoke-direct {v12, v2, v3, v13}, Llyiahf/vczjk/s71;-><init>(Llyiahf/vczjk/t81;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    check-cast v12, Llyiahf/vczjk/ze3;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v7, v12}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7}, Llyiahf/vczjk/xr6;->OooOOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/hb8;

    move-result-object v11

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v12, v15

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-nez v12, :cond_15

    if-ne v15, v8, :cond_16

    :cond_15
    new-instance v15, Llyiahf/vczjk/t71;

    invoke-direct {v15, v11, v2, v13}, Llyiahf/vczjk/t71;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/t81;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v15, Llyiahf/vczjk/ze3;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v7, v15}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v11}, Llyiahf/vczjk/hb8;->OooO0OO()Z

    move-result v12

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v10, v13

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v10, :cond_17

    if-ne v13, v8, :cond_18

    :cond_17
    new-instance v13, Llyiahf/vczjk/oo0oO0;

    const/4 v10, 0x6

    invoke-direct {v13, v10, v2, v11}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v13, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v12, v13, v7, v9, v9}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    iget-object v10, v2, Llyiahf/vczjk/t81;->OooO0oo:Llyiahf/vczjk/s29;

    const/4 v12, 0x7

    invoke-static {v10, v7, v9, v12}, Llyiahf/vczjk/cp7;->OooOOO0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;

    move-result-object v10

    iget-object v13, v2, Llyiahf/vczjk/t81;->OooO:Llyiahf/vczjk/s29;

    invoke-static {v13, v7, v9, v12}, Llyiahf/vczjk/cp7;->OooOOO0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;

    move-result-object v13

    iget-object v15, v2, Llyiahf/vczjk/t81;->OooOO0O:Llyiahf/vczjk/s29;

    invoke-static {v15, v7, v9, v12}, Llyiahf/vczjk/cp7;->OooOOO0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;

    move-result-object v19

    new-instance v12, Llyiahf/vczjk/b6;

    const/16 v15, 0xb

    invoke-direct {v12, v15, v10, v3}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v3, 0x5df22cdd

    invoke-static {v3, v12, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    new-instance v15, Llyiahf/vczjk/a6;

    const/16 v20, 0x2

    move-object/from16 v17, v2

    move-object/from16 v16, v10

    move-object/from16 v18, v11

    invoke-direct/range {v15 .. v20}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v3, v16

    const v10, 0x529aae46

    invoke-static {v10, v15, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    const v11, -0x6815fd56

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v11, v15

    and-int/lit8 v0, v0, 0xe

    if-eq v0, v1, :cond_19

    move v14, v9

    :cond_19
    or-int v0, v11, v14

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_1a

    if-ne v1, v8, :cond_1b

    :cond_1a
    new-instance v1, Llyiahf/vczjk/x5;

    const/4 v0, 0x3

    invoke-direct {v1, v2, v4, v0, v3}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    move-object v11, v1

    check-cast v11, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v0, Llyiahf/vczjk/g81;

    move-object v1, v2

    move-object v2, v13

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/g81;-><init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/r71;)V

    const v1, -0x23fea0d9

    invoke-static {v1, v0, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v15

    move-object v8, v12

    const/4 v12, 0x0

    const/4 v14, 0x0

    move-object/from16 v16, v7

    const/4 v7, 0x0

    move-object v9, v10

    const/4 v10, 0x0

    const v17, 0x60001b0

    move-object/from16 v13, v18

    const/16 v18, 0xa9

    invoke-static/range {v7 .. v18}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_9
    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_1c

    new-instance v1, Llyiahf/vczjk/c4;

    const/16 v2, 0x8

    invoke-direct {v1, v6, v2, v4}, Llyiahf/vczjk/c4;-><init>(IILjava/lang/Object;)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1c
    return-void

    :cond_1d
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooOoo(Llyiahf/vczjk/e71;Llyiahf/vczjk/r71;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 39

    move-object/from16 v2, p1

    move/from16 v1, p3

    move/from16 v4, p4

    move-object/from16 v0, p5

    move-object/from16 v7, p6

    move-object/from16 v15, p7

    check-cast v15, Llyiahf/vczjk/zf1;

    const v3, 0x112acb1e

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int v3, p8, v3

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    if-eqz v8, :cond_1

    const/16 v8, 0x100

    goto :goto_1

    :cond_1
    const/16 v8, 0x80

    :goto_1
    or-int/2addr v3, v8

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    if-eqz v8, :cond_2

    const/16 v8, 0x800

    goto :goto_2

    :cond_2
    const/16 v8, 0x400

    :goto_2
    or-int/2addr v3, v8

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    const/16 v8, 0x4000

    goto :goto_3

    :cond_3
    const/16 v8, 0x2000

    :goto_3
    or-int/2addr v3, v8

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_4

    const/high16 v8, 0x20000

    goto :goto_4

    :cond_4
    const/high16 v8, 0x10000

    :goto_4
    or-int/2addr v3, v8

    const v8, 0x12493

    and-int/2addr v8, v3

    const v13, 0x12492

    if-ne v8, v13, :cond_6

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v6, p2

    goto/16 :goto_1e

    :cond_6
    :goto_5
    const v8, 0x6e3c21fe

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    sget-object v14, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v13, v14, :cond_7

    iget-object v13, v2, Llyiahf/vczjk/e71;->OooOOO:Landroid/content/ComponentName;

    invoke-virtual {v13}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v13, Ljava/lang/String;

    const/4 v5, 0x0

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v13}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v9, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Landroid/content/Context;

    invoke-static {v15}, Llyiahf/vczjk/jp8;->Oooo0oO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/oj2;

    move-result-object v12

    invoke-static {v15}, Llyiahf/vczjk/zsa;->ooOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/zh1;

    move-result-object v19

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_keep_service_smart_standby:I

    invoke-static {v10, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v10

    const-string v11, "KEEP "

    invoke-virtual {v11, v13}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v14, :cond_8

    new-instance v8, Llyiahf/vczjk/ow;

    const/16 v5, 0x13

    invoke-direct {v8, v5}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v8, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v5, 0x4c5de2

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v23

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v23, :cond_9

    if-ne v5, v14, :cond_a

    :cond_9
    new-instance v5, Llyiahf/vczjk/q71;

    const/4 v1, 0x0

    invoke-direct {v5, v9, v1}, Llyiahf/vczjk/q71;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v5, Llyiahf/vczjk/oe3;

    const/4 v1, 0x0

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v1, v12

    const/4 v12, 0x0

    move-object/from16 v23, v13

    const/4 v13, 0x0

    const/16 v25, 0x100

    const/16 v16, 0xc00

    const/high16 v26, 0x20000

    const/16 v17, 0x30

    move-object/from16 v31, v14

    move-object v14, v5

    move-object/from16 v5, v31

    move-object/from16 v31, v11

    move-object v11, v8

    move-object v8, v10

    move-object/from16 v10, v31

    move-object/from16 v33, v1

    move-object/from16 v32, v9

    move-object/from16 v9, v19

    move-object/from16 v31, v23

    const v1, 0x6e3c21fe

    invoke-static/range {v8 .. v17}, Llyiahf/vczjk/zsa;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/zh1;Ljava/lang/Object;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v15}, Llyiahf/vczjk/zsa;->ooOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/zh1;

    move-result-object v8

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_add_lock_white_list:I

    invoke-static {v10, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v10

    move-object v9, v8

    move-object v8, v10

    iget-object v10, v2, Llyiahf/vczjk/e71;->OooOOO:Landroid/content/ComponentName;

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v5, :cond_b

    new-instance v1, Llyiahf/vczjk/ow;

    const/16 v11, 0x14

    invoke-direct {v1, v11}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v11, v1

    check-cast v11, Llyiahf/vczjk/oe3;

    const/4 v1, 0x0

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v1, 0x4c5de2

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v12, v32

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_c

    if-ne v14, v5, :cond_d

    :cond_c
    new-instance v14, Llyiahf/vczjk/q71;

    const/4 v13, 0x1

    invoke-direct {v14, v12, v13}, Llyiahf/vczjk/q71;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v32, v12

    const/4 v12, 0x0

    move/from16 v22, v13

    const/4 v13, 0x0

    const/16 v17, 0x30

    move-object/from16 v35, v19

    move/from16 v1, v22

    move-object/from16 v34, v32

    invoke-static/range {v8 .. v17}, Llyiahf/vczjk/zsa;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/zh1;Ljava/lang/Object;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object v8, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v10, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v10, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v1, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v15, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_e

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_e
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v15, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v11, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_f

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    move-object/from16 v16, v9

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v4, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_10

    goto :goto_7

    :cond_f
    move-object/from16 v16, v9

    :goto_7
    invoke-static {v1, v15, v1, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v12, v15, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v12, 0x3f800000    # 1.0f

    invoke-static {v8, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v4, 0x44

    int-to-float v4, v4

    const/4 v12, 0x0

    const/4 v6, 0x2

    invoke-static {v1, v4, v12, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    const v4, -0x615d173a

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v4, 0xe000

    and-int/2addr v4, v3

    const/16 v6, 0x4000

    const/16 v32, 0x1

    if-ne v4, v6, :cond_11

    move/from16 v6, v32

    goto :goto_8

    :cond_11
    const/4 v6, 0x0

    :goto_8
    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v6, v6, v19

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v6, :cond_12

    if-ne v12, v5, :cond_13

    :cond_12
    new-instance v12, Llyiahf/vczjk/oo0oO0;

    const/4 v6, 0x7

    invoke-direct {v12, v6, v0, v2}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v12, Llyiahf/vczjk/le3;

    const/4 v6, 0x0

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v6, -0x48fade91

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v6, v3, 0x380

    const/16 v0, 0x100

    if-ne v6, v0, :cond_14

    move/from16 v0, v32

    :goto_9
    const/16 v6, 0x4000

    goto :goto_a

    :cond_14
    const/4 v0, 0x0

    goto :goto_9

    :goto_a
    if-ne v4, v6, :cond_15

    move/from16 v4, v32

    goto :goto_b

    :cond_15
    const/4 v4, 0x0

    :goto_b
    or-int/2addr v0, v4

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v0, v4

    and-int/lit16 v4, v3, 0x1c00

    const/16 v6, 0x800

    if-ne v4, v6, :cond_16

    move/from16 v4, v32

    goto :goto_c

    :cond_16
    const/4 v4, 0x0

    :goto_c
    or-int/2addr v0, v4

    move-object/from16 v4, v33

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_18

    if-ne v6, v5, :cond_17

    goto :goto_d

    :cond_17
    move-object/from16 v38, v1

    move-object v1, v2

    move/from16 v33, v3

    move-object/from16 v36, v5

    move-object v0, v6

    const/4 v6, 0x0

    goto :goto_e

    :cond_18
    :goto_d
    new-instance v0, Llyiahf/vczjk/m71;

    move-object/from16 v38, v1

    move/from16 v33, v3

    move-object/from16 v36, v5

    const/4 v6, 0x0

    move/from16 v1, p3

    move-object v3, v2

    move-object v5, v4

    move/from16 v4, p4

    move-object/from16 v2, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/m71;-><init>(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/e71;ZLlyiahf/vczjk/oj2;)V

    move-object v1, v3

    move-object v4, v5

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_e
    check-cast v0, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v2, v38

    invoke-static {v2, v12, v0}, Landroidx/compose/foundation/OooO00o;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    const v2, 0x3ff87cd9

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz p3, :cond_19

    if-eqz p4, :cond_19

    sget-object v2, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/x21;

    iget-wide v2, v2, Llyiahf/vczjk/x21;->OooO0oo:J

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v8, v2, v3, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    goto :goto_f

    :cond_19
    move-object v2, v8

    :goto_f
    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v0, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/16 v2, 0x10

    int-to-float v2, v2

    const/4 v3, 0x2

    const/4 v5, 0x0

    invoke-static {v0, v2, v5, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v5, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v12, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    const/16 v3, 0x36

    invoke-static {v12, v5, v15, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v12, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v15, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v23, v2

    iget-boolean v2, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_1a

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_1a
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    invoke-static {v3, v15, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_1b

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1c

    :cond_1b
    invoke-static {v12, v15, v12, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    invoke-static {v0, v15, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v0, 0x4c5de2

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_1d

    move-object/from16 v0, v36

    if-ne v2, v0, :cond_1e

    goto :goto_11

    :cond_1d
    move-object/from16 v0, v36

    :goto_11
    invoke-virtual {v1}, Llyiahf/vczjk/e71;->OooO00o()Z

    move-result v2

    xor-int/lit8 v2, v2, 0x1

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-static {v2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1e
    check-cast v2, Llyiahf/vczjk/qs5;

    const/4 v6, 0x0

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/high16 v3, 0x3f800000    # 1.0f

    float-to-double v6, v3

    const-wide/16 v17, 0x0

    cmpl-double v6, v6, v17

    if-lez v6, :cond_1f

    goto :goto_12

    :cond_1f
    const-string v6, "invalid weight; must be greater than zero"

    invoke-static {v6}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_12
    new-instance v6, Landroidx/compose/foundation/layout/LayoutWeightElement;

    move/from16 v7, v32

    invoke-direct {v6, v3, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    const/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v21, 0x0

    const/16 v25, 0xb

    move-object/from16 v20, v6

    invoke-static/range {v20 .. v25}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v6, 0x8

    int-to-float v6, v6

    const/4 v12, 0x0

    invoke-static {v3, v12, v6, v7}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v7, 0x30

    invoke-static {v6, v5, v15, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v12

    iget v7, v15, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v36, v4

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v15, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v37, v0

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v0, :cond_20

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_13

    :cond_20
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_13
    invoke-static {v12, v15, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_21

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_22

    :cond_21
    invoke-static {v7, v15, v7, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_22
    invoke-static {v3, v15, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v4, 0x0

    invoke-static {v0, v3, v15, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v0

    iget v3, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v15, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_23

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_23
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    invoke-static {v0, v15, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_24

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_25

    :cond_24
    invoke-static {v3, v15, v3, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_25
    invoke-static {v7, v15, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v0, 0x30

    invoke-static {v6, v5, v15, v0}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v3, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v15, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_26

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_15

    :cond_26
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_15
    invoke-static {v0, v15, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_27

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_28

    :cond_27
    invoke-static {v3, v15, v3, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_28
    invoke-static {v5, v15, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v8, v1, Llyiahf/vczjk/e71;->OooOOOO:Ljava/lang/String;

    const-string v0, "getLabel(...)"

    invoke-static {v8, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n6a;

    iget-object v3, v3, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v25, 0x0

    const/16 v28, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    move-object/from16 v27, v15

    const/4 v15, 0x0

    move-object/from16 v20, v16

    const-wide/16 v16, 0x0

    const/16 v18, 0x0

    move-object/from16 v4, v20

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v29, 0x0

    const v30, 0x1fffe

    move-object/from16 v26, v3

    invoke-static/range {v8 .. v30}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v27

    const v3, -0x27a8e557

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v1, Llyiahf/vczjk/e71;->OooOOo:Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    iget-object v5, v3, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;->OooOOOO:Ljava/lang/String;

    if-eqz v5, :cond_29

    invoke-virtual {v5}, Ljava/lang/String;->length()I

    move-result v5

    if-lez v5, :cond_29

    const/4 v6, 0x0

    invoke-static {v3, v15, v6}, Llyiahf/vczjk/zsa;->OooO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/rf1;I)V

    goto :goto_16

    :cond_29
    const/4 v6, 0x0

    :goto_16
    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, -0x27a8c89e

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v1, Llyiahf/vczjk/e71;->OooOOoo:Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    if-nez v3, :cond_2a

    goto :goto_17

    :cond_2a
    invoke-static {v3, v15, v6}, Llyiahf/vczjk/zsa;->OooO0O0(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/rf1;I)V

    :goto_17
    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, -0x27a8b6df

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    const/4 v5, 0x0

    if-nez v3, :cond_2b

    iget-boolean v3, v1, Llyiahf/vczjk/e71;->OooOOo0:Z

    if-eqz v3, :cond_2b

    const/4 v6, 0x0

    invoke-static {v6, v15}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_disabled_by_thanox:I

    invoke-static {v3, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const/4 v7, 0x2

    invoke-static {v6, v7, v3, v15, v5}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_18

    :cond_2b
    const/4 v6, 0x0

    :goto_18
    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, -0x27a895f7

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x1

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v8, v1, Llyiahf/vczjk/e71;->OooOOO0:Ljava/lang/String;

    const-string v3, "getName(...)"

    invoke-static {v8, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n6a;

    iget-object v0, v0, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const/16 v25, 0x0

    const/16 v28, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    move-object/from16 v27, v15

    const/4 v15, 0x0

    const-wide/16 v16, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v29, 0x0

    const v30, 0x1fffe

    move-object/from16 v26, v0

    invoke-static/range {v8 .. v30}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v27

    const/4 v7, 0x1

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    const v0, -0x6815fd56

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    const/high16 v3, 0x70000

    and-int v3, v33, v3

    const/high16 v6, 0x20000

    if-ne v3, v6, :cond_2c

    const/4 v3, 0x1

    goto :goto_19

    :cond_2c
    const/4 v3, 0x0

    :goto_19
    or-int/2addr v0, v3

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v0, v3

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v0, :cond_2e

    move-object/from16 v0, v37

    if-ne v3, v0, :cond_2d

    goto :goto_1a

    :cond_2d
    move-object/from16 v7, p6

    goto :goto_1b

    :cond_2e
    move-object/from16 v0, v37

    :goto_1a
    new-instance v3, Llyiahf/vczjk/oo0ooO;

    move-object/from16 v7, p6

    invoke-direct {v3, v7, v1, v2}, Llyiahf/vczjk/oo0ooO;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/e71;Llyiahf/vczjk/qs5;)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_1b
    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/oe3;

    const/4 v6, 0x0

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v10, 0x0

    const/4 v14, 0x0

    move-object/from16 v27, v15

    const/16 v15, 0x7c

    move-object/from16 v13, v27

    invoke-static/range {v8 .. v15}, Landroidx/compose/material3/OooO0O0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rf1;II)V

    move-object v15, v13

    const/4 v2, 0x1

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/gj2;

    const v3, 0x1040001

    invoke-static {v3, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/c71;->OooOOO0:Llyiahf/vczjk/c71;

    invoke-direct {v2, v3, v6}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    const v3, 0x3ff9d105

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/r71;->OooOOOO:Llyiahf/vczjk/r71;

    move-object/from16 v6, p2

    if-ne v6, v3, :cond_2f

    new-instance v3, Llyiahf/vczjk/gj2;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_keep_service_smart_standby:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/c71;->OooOOO:Llyiahf/vczjk/c71;

    invoke-direct {v3, v8, v9}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    :goto_1c
    const/4 v13, 0x0

    goto :goto_1d

    :cond_2f
    move-object v3, v5

    goto :goto_1c

    :goto_1d
    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x3ff9fd5a

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v8, Llyiahf/vczjk/r71;->OooOOO0:Llyiahf/vczjk/r71;

    if-ne v6, v8, :cond_30

    new-instance v5, Llyiahf/vczjk/gj2;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_add_lock_white_list:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/c71;->OooOOOO:Llyiahf/vczjk/c71;

    invoke-direct {v5, v8, v9}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    :cond_30
    const/4 v13, 0x0

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    filled-new-array {v2, v3, v5}, [Llyiahf/vczjk/gj2;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/sy;->o0OO00O([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v2

    const v3, -0x48fade91

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v12, v34

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    move-object/from16 v13, v31

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    move-object/from16 v9, v35

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v3, :cond_31

    if-ne v5, v0, :cond_32

    :cond_31
    new-instance v16, Llyiahf/vczjk/m60;

    const/16 v21, 0x1

    move-object/from16 v20, v4

    move-object/from16 v19, v9

    move-object/from16 v17, v12

    move-object/from16 v18, v13

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/m60;-><init>(Landroid/content/Context;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/w41;I)V

    move-object/from16 v5, v16

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_32
    move-object v3, v5

    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v5, 0x200

    const/4 v0, 0x0

    move-object v4, v15

    move-object/from16 v1, v36

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/jp8;->OooO0OO(FLlyiahf/vczjk/oj2;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    const/4 v2, 0x1

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1e
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_33

    new-instance v0, Llyiahf/vczjk/n71;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v4, p3

    move/from16 v5, p4

    move/from16 v8, p8

    move-object v3, v6

    move-object/from16 v6, p5

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/n71;-><init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/e71;Llyiahf/vczjk/r71;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;I)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_33
    return-void
.end method

.method public final OooOooO(Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;ZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 32

    move-object/from16 v2, p1

    move/from16 v3, p2

    move/from16 v7, p3

    move-object/from16 v6, p4

    move-object/from16 v8, p8

    check-cast v8, Llyiahf/vczjk/zf1;

    const v0, -0x1033e3b9

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v9, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v9

    :goto_0
    or-int v0, p9, v0

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    invoke-virtual {v8, v7}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x100

    goto :goto_2

    :cond_2
    const/16 v1, 0x80

    :goto_2
    or-int/2addr v0, v1

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    const/16 v1, 0x800

    goto :goto_3

    :cond_3
    const/16 v1, 0x400

    :goto_3
    or-int/2addr v0, v1

    move/from16 v1, p5

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    const/16 v13, 0x4000

    if-eqz v5, :cond_4

    move v5, v13

    goto :goto_4

    :cond_4
    const/16 v5, 0x2000

    :goto_4
    or-int/2addr v0, v5

    move/from16 v5, p6

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v14

    const/high16 v15, 0x20000

    if-eqz v14, :cond_5

    move v14, v15

    goto :goto_5

    :cond_5
    const/high16 v14, 0x10000

    :goto_5
    or-int/2addr v0, v14

    move-object/from16 v14, p7

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    const/high16 v10, 0x100000

    if-eqz v16, :cond_6

    move/from16 v16, v10

    goto :goto_6

    :cond_6
    const/high16 v16, 0x80000

    :goto_6
    or-int v0, v0, v16

    const v16, 0x92493

    and-int v11, v0, v16

    const v12, 0x92492

    if-ne v11, v12, :cond_8

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v11

    if-nez v11, :cond_7

    goto :goto_7

    :cond_7
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v11, v6

    move v10, v7

    move-object v6, v8

    goto/16 :goto_19

    :cond_8
    :goto_7
    sget-object v11, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v12, 0x3f800000    # 1.0f

    invoke-static {v11, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v11

    const/16 v12, 0x28

    int-to-float v12, v12

    const/4 v4, 0x0

    invoke-static {v11, v12, v4, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/x21;

    iget-wide v4, v12, Llyiahf/vczjk/x21;->OooOOo:J

    sget-object v12, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v11, v4, v5, v12}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const v4, -0x48fade91

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v4, 0xe000

    and-int/2addr v4, v0

    const/4 v12, 0x0

    const/4 v5, 0x1

    if-ne v4, v13, :cond_9

    move v4, v5

    goto :goto_8

    :cond_9
    move v4, v12

    :goto_8
    const/high16 v13, 0x380000

    and-int/2addr v13, v0

    if-ne v13, v10, :cond_a

    move v10, v5

    goto :goto_9

    :cond_a
    move v10, v12

    :goto_9
    or-int/2addr v4, v10

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v4, v10

    const/high16 v10, 0x70000

    and-int/2addr v10, v0

    if-ne v10, v15, :cond_b

    move v10, v5

    goto :goto_a

    :cond_b
    move v10, v12

    :goto_a
    or-int/2addr v4, v10

    and-int/lit8 v10, v0, 0x70

    const/16 v13, 0x20

    if-ne v10, v13, :cond_c

    move v10, v5

    goto :goto_b

    :cond_c
    move v10, v12

    :goto_b
    or-int/2addr v4, v10

    and-int/lit16 v10, v0, 0x1c00

    const/16 v13, 0x800

    if-ne v10, v13, :cond_d

    move v15, v5

    goto :goto_c

    :cond_d
    move v15, v12

    :goto_c
    or-int/2addr v4, v15

    and-int/lit16 v15, v0, 0x380

    const/16 v0, 0x100

    if-ne v15, v0, :cond_e

    move/from16 v16, v5

    goto :goto_d

    :cond_e
    move/from16 v16, v12

    :goto_d
    or-int v4, v4, v16

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    move/from16 v16, v10

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v4, :cond_10

    if-ne v0, v10, :cond_f

    goto :goto_e

    :cond_f
    move-object v1, v2

    const/4 v14, 0x0

    const/16 v17, 0x100

    goto :goto_f

    :cond_10
    :goto_e
    new-instance v0, Llyiahf/vczjk/o71;

    move/from16 v4, p6

    move v5, v3

    const/16 v17, 0x100

    move-object v3, v2

    move-object v2, v14

    const/4 v14, 0x0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o71;-><init>(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;Z)V

    move-object v1, v3

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_f
    check-cast v0, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v2, 0x7

    const/4 v3, 0x0

    invoke-static {v11, v12, v3, v0, v2}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/16 v2, 0x10

    int-to-float v2, v2

    invoke-static {v0, v2, v14, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    const/16 v4, 0x36

    invoke-static {v3, v2, v8, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v8, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_11

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_11
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_12

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_13

    :cond_12
    invoke-static {v4, v8, v4, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_13
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v0, 0x3f800000    # 1.0f

    float-to-double v13, v0

    const-wide/16 v18, 0x0

    cmpl-double v11, v13, v18

    if-lez v11, :cond_14

    goto :goto_11

    :cond_14
    const-string v11, "invalid weight; must be greater than zero"

    invoke-static {v11}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_11
    new-instance v11, Landroidx/compose/foundation/layout/LayoutWeightElement;

    invoke-direct {v11, v0, v12}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    sget-object v0, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v13, 0x30

    invoke-static {v0, v2, v8, v13}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v2, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v8, v11}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_15

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_12

    :cond_15
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_12
    invoke-static {v0, v8, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v13, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_16

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_17

    :cond_16
    invoke-static {v2, v8, v2, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_17
    invoke-static {v11, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v0, v1, Llyiahf/vczjk/b71;->OooO00o:Llyiahf/vczjk/g71;

    invoke-static {v0, v8, v12}, Llyiahf/vczjk/zsa;->OooOOOO(Llyiahf/vczjk/g71;Llyiahf/vczjk/rf1;I)V

    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    iget-object v0, v0, Llyiahf/vczjk/g71;->OooO00o:Ljava/lang/String;

    iget-object v2, v1, Llyiahf/vczjk/b71;->OooO0O0:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " ("

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, ")"

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooO:Llyiahf/vczjk/rn9;

    move/from16 v3, v17

    const/16 v17, 0x0

    const/16 v20, 0x0

    const/4 v1, 0x0

    move-object/from16 v18, v2

    move v4, v3

    const-wide/16 v2, 0x0

    move v6, v4

    const-wide/16 v4, 0x0

    move v7, v6

    const/4 v6, 0x0

    move v11, v7

    const/4 v7, 0x0

    move-object/from16 v19, v8

    const/16 v13, 0x800

    const-wide/16 v8, 0x0

    move-object v14, v10

    const/4 v10, 0x0

    move/from16 v21, v11

    move/from16 v22, v12

    const-wide/16 v11, 0x0

    move/from16 v23, v13

    const/4 v13, 0x0

    move-object/from16 v24, v14

    const/4 v14, 0x0

    move/from16 v25, v15

    const/4 v15, 0x0

    move/from16 v26, v16

    const/16 v16, 0x0

    move/from16 v27, v21

    const/16 v21, 0x0

    move/from16 v28, v22

    const v22, 0x1fffe

    move-object/from16 v31, v24

    move/from16 v30, v25

    move/from16 v29, v26

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v6, v19

    const/4 v9, 0x1

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v0, 0x64abb247

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz p2, :cond_1c

    const v0, -0x615d173a

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move/from16 v0, v29

    const/16 v13, 0x800

    if-ne v0, v13, :cond_18

    move v12, v9

    :goto_13
    move/from16 v0, v30

    const/16 v7, 0x100

    goto :goto_14

    :cond_18
    const/4 v12, 0x0

    goto :goto_13

    :goto_14
    if-ne v0, v7, :cond_19

    move v0, v9

    goto :goto_15

    :cond_19
    const/4 v0, 0x0

    :goto_15
    or-int/2addr v0, v12

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_1b

    move-object/from16 v14, v31

    if-ne v1, v14, :cond_1a

    goto :goto_16

    :cond_1a
    move/from16 v10, p3

    move-object/from16 v11, p4

    goto :goto_17

    :cond_1b
    :goto_16
    new-instance v1, Llyiahf/vczjk/ev0;

    const/4 v0, 0x1

    move/from16 v10, p3

    move-object/from16 v11, p4

    invoke-direct {v1, v11, v10, v0}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_17
    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/le3;

    const/4 v12, 0x0

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/l81;

    invoke-direct {v1, v10}, Llyiahf/vczjk/l81;-><init>(Z)V

    const v2, 0x3fca294a

    invoke-static {v2, v1, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/high16 v7, 0x180000

    const/16 v8, 0x3e

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    goto :goto_18

    :cond_1c
    move/from16 v10, p3

    move-object/from16 v11, p4

    const/4 v12, 0x0

    :goto_18
    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_19
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v12

    if-eqz v12, :cond_1d

    new-instance v0, Llyiahf/vczjk/p71;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v3, p2

    move/from16 v6, p5

    move/from16 v7, p6

    move-object/from16 v8, p7

    move/from16 v9, p9

    move v4, v10

    move-object v5, v11

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/p71;-><init>(Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;ZZLlyiahf/vczjk/ze3;I)V

    iput-object v0, v12, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1d
    return-void
.end method

.method public final getApplicationContext()Landroid/content/Context;
    .locals 3

    new-instance v0, Llyiahf/vczjk/wo9;

    invoke-super {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    const-string v2, "getApplicationContext(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Landroid/content/ContextWrapper;-><init>(Landroid/content/Context;)V

    return-object v0
.end method

.method public final onResume()V
    .locals 6

    invoke-super {p0}, Landroidx/fragment/app/FragmentActivity;->onResume()V

    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v0

    const-string v1, "app"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getFlags()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "ComponentManager - "

    invoke-static {v1, v0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/n27;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x0

    invoke-virtual {p0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v1

    invoke-interface {v1, v0, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_2

    :goto_0
    return-void

    :cond_2
    new-instance v1, Llyiahf/vczjk/kd5;

    invoke-direct {v1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_app_component_manager:I

    invoke-virtual {v1, v3}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->feature_desc_app_component_manager:I

    invoke-virtual {v1, v3}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    iget-object v3, v1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s3;

    iput-boolean v2, v3, Llyiahf/vczjk/s3;->OooOOO0:Z

    const v2, 0x104000a

    const/4 v4, 0x0

    invoke-virtual {v1, v2, v4}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    new-instance v2, Llyiahf/vczjk/w0;

    const/4 v4, 0x4

    invoke-direct {v2, p0, v4}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    const/high16 v4, 0x1040000

    invoke-virtual {v1, v4, v2}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->title_remember:I

    new-instance v4, Llyiahf/vczjk/x0;

    const/4 v5, 0x1

    invoke-direct {v4, v5, p0, v0}, Llyiahf/vczjk/x0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v0, v3, Llyiahf/vczjk/s3;->OooO00o:Landroid/view/ContextThemeWrapper;

    invoke-virtual {v0, v2}, Landroid/content/Context;->getText(I)Ljava/lang/CharSequence;

    move-result-object v0

    iput-object v0, v3, Llyiahf/vczjk/s3;->OooOO0O:Ljava/lang/CharSequence;

    iput-object v4, v3, Llyiahf/vczjk/s3;->OooOO0o:Landroid/content/DialogInterface$OnClickListener;

    invoke-virtual {v1}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    move-result-object v0

    new-instance v1, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-direct {v1, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    const/16 v2, 0x12

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/nqa;->Oooo0O0(Landroid/os/Handler;Llyiahf/vczjk/x3;I)V

    return-void
.end method
