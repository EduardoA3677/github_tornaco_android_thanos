.class public final synthetic Llyiahf/vczjk/x0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/x0;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/x0;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/x0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 5

    const/4 v0, 0x0

    const/4 v1, 0x1

    iget-object v2, p0, Llyiahf/vczjk/x0;->OooOOO:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/x0;->OooOOOO:Ljava/lang/Object;

    iget v4, p0, Llyiahf/vczjk/x0;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    sget p1, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->OoooO00:I

    check-cast v3, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;

    invoke-virtual {v3}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/oOO0O0O;

    check-cast v2, Ljava/util/concurrent/atomic/AtomicInteger;

    const/16 v0, 0xc

    invoke-direct {p2, v0, v3, v2}, Llyiahf/vczjk/oOO0O0O;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p1, p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->ifServiceInstalled(Lutil/Consumer;)V

    return-void

    :pswitch_0
    sget v4, Lgithub/tornaco/thanos/android/ops/ops/by/ops/OpsAppListActivity;->OoooOO0:I

    check-cast v3, Lgithub/tornaco/thanos/android/ops/ops/by/ops/OpsAppListActivity;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

    if-ne p2, v1, :cond_0

    const/4 v0, 0x4

    :cond_0
    const/4 p1, 0x2

    if-ne p2, p1, :cond_1

    move v0, v1

    :cond_1
    invoke-virtual {v3}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/me6;

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p2, v3, v2, v0, v1}, Llyiahf/vczjk/me6;-><init>(Lgithub/tornaco/thanos/android/ops/ops/by/ops/OpsAppListActivity;Lgithub/tornaco/android/thanos/core/pm/AppInfo;II)V

    invoke-virtual {p1, p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->ifServiceInstalled(Lutil/Consumer;)V

    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v2, p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setStr(Ljava/lang/String;)V

    iget-object p1, v3, Lgithub/tornaco/thanos/android/ops/ops/by/ops/OpsAppListActivity;->OoooO0O:Llyiahf/vczjk/r41;

    invoke-virtual {p1}, Landroidx/recyclerview/widget/OooOO0O;->OooO0o()V

    return-void

    :pswitch_1
    check-cast v3, Llyiahf/vczjk/lr;

    iget-object p1, v3, Llyiahf/vczjk/lr;->OooOOoo:Ljava/lang/Object;

    check-cast p1, Lutil/Consumer;

    check-cast v2, Llyiahf/vczjk/ly2;

    iget-object p2, v2, Llyiahf/vczjk/ly2;->OooO0o:Ljava/lang/Object;

    check-cast p2, Ljava/lang/String;

    invoke-interface {p1, p2}, Lutil/Consumer;->accept(Ljava/lang/Object;)V

    return-void

    :pswitch_2
    sget p1, Lnow/fortuitous/thanos/launchother/LaunchOtherAppAskActivity;->Oooo0oO:I

    const-string p1, "IntentUri"

    check-cast v3, Lnow/fortuitous/thanos/launchother/LaunchOtherAppAskActivity;

    check-cast v2, Ljava/lang/String;

    invoke-static {v3, p1, v2}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :pswitch_3
    check-cast v3, Lnow/fortuitous/thanos/infinite/InfiniteZActivity;

    iget-object p1, v3, Lnow/fortuitous/thanos/infinite/InfiniteZActivity;->Oooo0oO:Llyiahf/vczjk/x70;

    new-instance p2, Llyiahf/vczjk/py3;

    invoke-direct {p2, v3, v0}, Llyiahf/vczjk/py3;-><init>(Lnow/fortuitous/thanos/infinite/InfiniteZActivity;I)V

    new-instance v1, Llyiahf/vczjk/qy3;

    invoke-direct {v1, v3, v0}, Llyiahf/vczjk/qy3;-><init>(Lnow/fortuitous/thanos/infinite/InfiniteZActivity;I)V

    invoke-virtual {p1}, Llyiahf/vczjk/x70;->OooO0o()Lgithub/tornaco/android/thanos/core/app/infinite/InfiniteZManager;

    move-result-object v0

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/w70;

    invoke-direct {v3, p1, p2, v1}, Llyiahf/vczjk/w70;-><init>(Llyiahf/vczjk/x70;Llyiahf/vczjk/py3;Llyiahf/vczjk/qy3;)V

    invoke-virtual {v0, v2, v3}, Lgithub/tornaco/android/thanos/core/app/infinite/InfiniteZManager;->removePackage(Ljava/lang/String;Lgithub/tornaco/android/thanos/core/app/infinite/RemovePackageCallback;)V

    return-void

    :pswitch_4
    check-cast v3, Landroid/widget/EditText;

    invoke-virtual {v3}, Landroid/widget/TextView;->getEditableText()Landroid/text/Editable;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    check-cast v2, Lutil/Consumer;

    invoke-interface {v2, p1}, Lutil/Consumer;->accept(Ljava/lang/Object;)V

    return-void

    :pswitch_5
    const-string p1, "error"

    check-cast v3, Landroid/content/Context;

    check-cast v2, Ljava/lang/String;

    invoke-static {v3, p1, v2}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :pswitch_6
    sget p1, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    check-cast v3, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-static {v3}, Llyiahf/vczjk/n27;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v3, p1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    const-string p2, "getDefaultSharedPreferences(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    check-cast v2, Ljava/lang/String;

    invoke-interface {p1, v2, v1}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    return-void

    :pswitch_7
    sget-object v4, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;->OoooO00:Ljava/lang/String;

    check-cast v3, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

    check-cast v2, Ljava/lang/String;

    if-nez p2, :cond_2

    iget-object p1, v3, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;->Oooo0oo:Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p2, "com.a.c/.xxx"

    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/pm/ComponentNameBrief;->unflattenFromString(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/ComponentNameBrief;

    move-result-object p2

    invoke-static {p2}, Lutil/JsonFormatter;->toPrettyJson(Ljava/lang/Object;)Ljava/lang/String;

    iget-object p2, p1, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    new-instance v3, Llyiahf/vczjk/s0;

    const/16 v4, 0x19

    invoke-direct {v3, v4, p1, v2}, Llyiahf/vczjk/s0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/lp8;

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/lp8;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v0

    new-instance v3, Llyiahf/vczjk/lq8;

    invoke-direct {v3, v2, v0, v1}, Llyiahf/vczjk/lq8;-><init>(Llyiahf/vczjk/jp8;Llyiahf/vczjk/i88;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/jp8;->OoooOOo(Llyiahf/vczjk/i88;)Llyiahf/vczjk/lq8;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/wx9;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/wx9;-><init>(Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;I)V

    new-instance p1, Llyiahf/vczjk/rl1;

    invoke-direct {p1, v2}, Llyiahf/vczjk/rl1;-><init>(Llyiahf/vczjk/nl1;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    new-instance p1, Llyiahf/vczjk/o0OO000o;

    invoke-direct {p1, v1, v3, v2}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {p2}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object p2

    invoke-interface {p2}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/cm4;

    iget-boolean p2, p2, Llyiahf/vczjk/cm4;->OooO00o:Z

    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o0OO000o;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_0
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
