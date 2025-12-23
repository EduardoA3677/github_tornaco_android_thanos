.class public final synthetic Llyiahf/vczjk/oO0Oo0o0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/up8;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/a;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a;Landroid/content/Intent;ILjava/lang/String;ILjava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO0:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo:Ljava/lang/Object;

    iput p3, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO:I

    iput-object p4, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOO:Ljava/lang/String;

    iput p5, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOo:I

    iput-object p6, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo0:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO0:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOO:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo0:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo:Ljava/lang/Object;

    iput p5, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO:I

    iput p6, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO0:Llyiahf/vczjk/a;

    iget v1, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO:I

    iget v2, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOo:I

    const/4 v3, 0x0

    if-ne v1, v2, :cond_0

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_SAME_CALLING_UID:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOO:Ljava/lang/String;

    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_1

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_BAD_ARGS:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_1
    iget-object v4, v0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v5, v4, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/uv6;->isPkgInWhiteList(Ljava/lang/String;)Z

    move-result v5

    if-nez v5, :cond_12

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->isSystemOrPhoneOrShell(I)Z

    move-result v5

    if-eqz v5, :cond_2

    goto/16 :goto_1

    :cond_2
    iget-object v5, v4, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/uv6;->OoooO00(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_3

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_XPOSED_MODULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_3
    invoke-static {v2, v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->from(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v1

    iget-object v5, v0, Llyiahf/vczjk/a;->OoooOO0:Ljava/util/HashSet;

    invoke-virtual {v5, v1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_BLOCK_API:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_4
    iget-object v5, v4, Llyiahf/vczjk/fo9;->OooOOo0:Lnow/fortuitous/app/OooO00o;

    invoke-virtual {v5}, Lnow/fortuitous/app/OooO00o;->getCurrentFrontApp()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_5

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_UI_PRESENT:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_5
    invoke-virtual {v0, v1}, Llyiahf/vczjk/a;->Oooo0OO(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    if-eqz v5, :cond_6

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_STRUGGLE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_6
    iget-boolean v5, v0, Llyiahf/vczjk/a;->OooOOo:Z

    if-nez v5, :cond_7

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_START_BLOCKED_DISABLED:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_7
    invoke-virtual {v0, v1}, Llyiahf/vczjk/a;->Oooo0o0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    if-eqz v5, :cond_8

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_PROCESS_RUNNING:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_8
    iget-object v5, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v5, v2}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->isDefaultSmsApp(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_9

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_SMS_APP:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_9
    iget-object v5, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo:Ljava/lang/Object;

    check-cast v5, Landroid/content/Intent;

    invoke-virtual {v5}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v6

    const-string v7, "android.intent.action.BOOT_COMPLETED"

    invoke-virtual {v7, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a

    iget-object v4, v4, Llyiahf/vczjk/fo9;->OooOoOO:Llyiahf/vczjk/i04;

    iget-object v4, v4, Llyiahf/vczjk/i04;->OooOOO0:Landroid/content/ComponentName;

    invoke-virtual {v4}, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_a

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_DEFAULT_IME_SERVICE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_a
    invoke-static {v2}, Llyiahf/vczjk/of7;->OooO00o(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_b

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_RECEIVED_PUSH:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_b
    iget-boolean v4, v0, Llyiahf/vczjk/a;->OooOOoo:Z

    if-eqz v4, :cond_10

    iget-object v4, v0, Llyiahf/vczjk/a;->OooooOO:Llyiahf/vczjk/qx7;

    if-eqz v4, :cond_10

    iget-object v4, v4, Llyiahf/vczjk/qx7;->OooOOO0:Ljava/lang/Object;

    check-cast v4, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-nez v4, :cond_c

    const-string v4, "ruleRepo is null..."

    invoke-static {v4}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_0

    :cond_c
    iget-object v6, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo0:Ljava/lang/String;

    invoke-static {v3, v2, v6}, Llyiahf/vczjk/qx7;->OooOOO0(Landroid/content/ComponentName;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v7

    invoke-interface {v4, v7}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_d

    new-instance v3, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v4, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BYPASS_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v3, v4, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto :goto_0

    :cond_d
    invoke-static {v2, v6}, Llyiahf/vczjk/qx7;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v6

    invoke-interface {v4, v6}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_e

    new-instance v3, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v4, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v3, v4, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto :goto_0

    :cond_e
    sget-object v6, Lgithub/tornaco/android/thanos/core/push/PushChannel;->FCM_GCM:Lgithub/tornaco/android/thanos/core/push/PushChannel;

    invoke-virtual {v6, v5}, Lgithub/tornaco/android/thanos/core/push/PushChannel;->match(Landroid/content/Intent;)Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-static {v2}, Llyiahf/vczjk/qx7;->OooOOO(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v5

    invoke-interface {v4, v5}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has([Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_f

    new-instance v3, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v4, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BYPASS_USER_RULE:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v3, v4, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    :cond_f
    :goto_0
    if-eqz v3, :cond_10

    move-object v0, v3

    goto :goto_2

    :cond_10
    iget-object v0, v0, Llyiahf/vczjk/a;->Oooo0OO:Llyiahf/vczjk/oOOo0000;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/dba;->OooO0O0(I)Lgithub/tornaco/android/thanos/core/persist/UserStringSetRepo;

    move-result-object v0

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/UserStringSetRepo;->has(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_11

    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BLOCKED_IN_BLOCK_LIST:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto :goto_2

    :cond_11
    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_DEFAULT:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    goto :goto_2

    :cond_12
    :goto_1
    new-instance v0, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    sget-object v1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->BY_PASS_WHITE_LISTED:Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;-><init>(Lgithub/tornaco/android/thanos/core/app/start/StartResult;Ljava/lang/String;)V

    :goto_2
    invoke-virtual {p1, v0}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 8

    move-object v2, p1

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    iget-object v1, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO0:Llyiahf/vczjk/a;

    iget-object p1, v1, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object p1, p1, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    iget-boolean p1, p1, Llyiahf/vczjk/k07;->OooOO0:Z

    if-nez p1, :cond_1

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOO:Ljava/lang/String;

    if-eqz v3, :cond_0

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/oOOO0O0o;

    iget-object v4, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo0:Ljava/lang/String;

    iget v6, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOO:I

    iget v7, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOOo:I

    iget-object p1, p0, Llyiahf/vczjk/oO0Oo0o0;->OooOOo:Ljava/lang/Object;

    move-object v5, p1

    check-cast v5, Ljava/lang/String;

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/oOOO0O0o;-><init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V

    new-instance p1, Llyiahf/vczjk/y51;

    const/4 v1, 0x1

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :cond_1
    :goto_0
    return-void
.end method
