.class public final synthetic Llyiahf/vczjk/n36;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ec9;
.implements Llyiahf/vczjk/t17;
.implements Lgithub/tornaco/android/thanos/core/util/function/Predicate;
.implements Llyiahf/vczjk/nl1;
.implements Lorg/apache/commons/io/function/IOTriFunction;
.implements Lorg/apache/commons/io/function/IOSupplier;
.implements Llyiahf/vczjk/u96;
.implements Llyiahf/vczjk/o0oo0000;
.implements Llyiahf/vczjk/j39;
.implements Lgithub/tornaco/android/thanos/core/util/function/Function;
.implements Lorg/apache/commons/io/function/IOTriConsumer;
.implements Lorg/apache/commons/io/function/IOFunction;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooOOO(Landroidx/preference/Preference;)V
    .locals 5

    iget-object p1, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/zs8;

    invoke-virtual {p1}, Landroidx/fragment/app/Oooo0;->requireContext()Landroid/content/Context;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->o00Ooo(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_3

    sget v0, Lnow/fortuitous/thanos/power/FreezeAllShortcutActivity;->OooOOO0:I

    new-instance v0, Landroid/content/Intent;

    const-class v1, Lnow/fortuitous/thanos/power/FreezeAllShortcutActivity;

    invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const/high16 v1, 0x10000000

    invoke-virtual {v0, v1}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    const-string v1, "android.intent.action.VIEW"

    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/R$drawable;->ic_nav_smart_freeze:I

    sget-object v3, Llyiahf/vczjk/es7;->OooO00o:Ljava/lang/ThreadLocal;

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Landroid/graphics/drawable/LayerDrawable;

    sget v3, Lgithub/tornaco/android/thanos/R$id;->settings_ic_foreground:I

    invoke-virtual {v2, v3}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    move-result-object v3

    if-eqz v3, :cond_0

    sget v4, Lgithub/tornaco/android/thanos/R$color;->nav_icon_smart_freeze:I

    invoke-virtual {p1, v4}, Landroid/content/Context;->getColor(I)I

    move-result v4

    invoke-virtual {v3, v4}, Landroid/graphics/drawable/Drawable;->setTint(I)V

    sget v4, Lgithub/tornaco/android/thanos/R$id;->settings_ic_foreground:I

    invoke-virtual {v2, v4, v3}, Landroid/graphics/drawable/LayerDrawable;->setDrawableByLayerId(ILandroid/graphics/drawable/Drawable;)Z

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/v34;->OoooO00(Landroid/graphics/drawable/Drawable;)Landroid/graphics/Bitmap;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Shortcut-freeze-all-"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/an8;

    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    iput-object p1, v3, Llyiahf/vczjk/an8;->OooO00o:Landroid/content/Context;

    iput-object v2, v3, Llyiahf/vczjk/an8;->OooO0O0:Ljava/lang/String;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {v1}, Landroidx/core/graphics/drawable/IconCompat;->OooO0O0(Landroid/graphics/Bitmap;)Landroidx/core/graphics/drawable/IconCompat;

    move-result-object v1

    iput-object v1, v3, Llyiahf/vczjk/an8;->OooO0oo:Landroidx/core/graphics/drawable/IconCompat;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->feature_category_app_clean_up:I

    invoke-virtual {p1, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v1

    iput-object v1, v3, Llyiahf/vczjk/an8;->OooO0o0:Ljava/lang/CharSequence;

    filled-new-array {v0}, [Landroid/content/Intent;

    move-result-object v0

    iput-object v0, v3, Llyiahf/vczjk/an8;->OooO0OO:[Landroid/content/Intent;

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_2

    iget-object v0, v3, Llyiahf/vczjk/an8;->OooO0OO:[Landroid/content/Intent;

    if-eqz v0, :cond_1

    array-length v0, v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Lgithub/tornaco/android/thanos/util/ShortcutReceiver;->OooO00o(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v0

    invoke-virtual {v0}, Landroid/app/PendingIntent;->getIntentSender()Landroid/content/IntentSender;

    move-result-object v0

    invoke-static {p1, v3, v0}, Llyiahf/vczjk/dn8;->oo000o(Landroid/content/Context;Llyiahf/vczjk/an8;Landroid/content/IntentSender;)V

    goto :goto_0

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Shortcut must have an intent"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Shortcut must have a non-empty label"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_0
    return-void

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/m46;

    invoke-virtual {p1}, Landroidx/fragment/app/Oooo0;->requireContext()Landroid/content/Context;

    move-result-object p1

    sget v0, Lgithub/tornaco/android/thanox/module/notification/recorder/AppListActivity;->OoooO0:I

    const-class v0, Lgithub/tornaco/android/thanox/module/notification/recorder/AppListActivity;

    invoke-static {p1, v0}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public OooOOOo()V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    sparse-switch v0, :sswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/start/StartRuleActivity;

    iget-object v0, v0, Lnow/fortuitous/thanos/start/StartRuleActivity;->Oooo0oO:Llyiahf/vczjk/f29;

    invoke-virtual {v0}, Llyiahf/vczjk/f29;->OooO0o()V

    return-void

    :sswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/power/StandByRuleActivity;

    iget-object v0, v0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {v0}, Llyiahf/vczjk/p09;->OooO0o()V

    return-void

    :sswitch_1
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    iget-object v0, v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->Oooo:Llyiahf/vczjk/w26;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/w26;->OooO0o0:Llyiahf/vczjk/v00;

    iget-object v0, v0, Llyiahf/vczjk/v00;->OooO0o:Llyiahf/vczjk/r00;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v2, :cond_0

    const-string v2, "Paging"

    const/4 v3, 0x3

    invoke-static {v2, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v3

    if-eqz v3, :cond_0

    const-string v3, "Refresh signal received"

    invoke-static {v2, v3, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/kn6;->OooO0OO:Llyiahf/vczjk/m7a;

    invoke-interface {v0}, Llyiahf/vczjk/m7a;->OooO00o()V

    return-void

    :cond_1
    const-string v0, "adapter"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    nop

    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_1
        0xb -> :sswitch_0
    .end sparse-switch
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 5

    iget-object p1, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ed9;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v1, 0x207

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v2

    const/16 v3, 0x40

    invoke-virtual {v0, v3}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/x04;->OooO0O0(Llyiahf/vczjk/x04;Llyiahf/vczjk/x04;)Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v1

    invoke-virtual {v0, v3}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/x04;->OooO0O0(Llyiahf/vczjk/x04;Llyiahf/vczjk/x04;)Llyiahf/vczjk/x04;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/ed9;->OooO0OO:Llyiahf/vczjk/x04;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/x04;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, p1, Llyiahf/vczjk/ed9;->OooO0Oo:Llyiahf/vczjk/x04;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/x04;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    :cond_0
    iput-object v2, p1, Llyiahf/vczjk/ed9;->OooO0OO:Llyiahf/vczjk/x04;

    iput-object v0, p1, Llyiahf/vczjk/ed9;->OooO0Oo:Llyiahf/vczjk/x04;

    iget-object p1, p1, Llyiahf/vczjk/ed9;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_2

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ob7;

    iget-object v1, v1, Llyiahf/vczjk/ob7;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    add-int/lit8 v2, v2, -0x1

    if-gez v2, :cond_1

    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    invoke-static {v2, v1}, Llyiahf/vczjk/q99;->OooO0Oo(ILjava/util/ArrayList;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_2
    return-object p2
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    iget v1, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    :pswitch_0
    sget v1, Lnow/fortuitous/thanos/ThanosApp;->OooOOOO:I

    check-cast v0, Llyiahf/vczjk/xm8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xm8;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_1
    check-cast p1, Lgithub/tornaco/android/thanos/core/os/RR;

    const-string v1, "rr"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/w45;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/w45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    sput p1, Llyiahf/vczjk/tn6;->OooO00o:I

    return-void

    :pswitch_2
    check-cast p1, Ljava/lang/Throwable;

    check-cast v0, Llyiahf/vczjk/yz2;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yz2;->accept(Ljava/lang/Object;)V

    return-void

    :pswitch_3
    sget v1, Lnow/fortuitous/profile/ProfileService$monitor$1;->OooOO0O:I

    check-cast v0, Llyiahf/vczjk/gu6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gu6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_4
    check-cast v0, Llyiahf/vczjk/r07;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r07;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_4
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    check-cast p1, [B

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    check-cast p3, Ljava/lang/Integer;

    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    move-result p3

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/output/UncheckedFilterOutputStream;

    invoke-static {v0, p1, p2, p3}, Lorg/apache/commons/io/output/UncheckedFilterOutputStream;->OooOOOO(Lorg/apache/commons/io/output/UncheckedFilterOutputStream;[BII)V

    return-void
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/function/IOBaseStream;

    check-cast p1, Lorg/apache/commons/io/function/IORunnable;

    invoke-interface {v0, p1}, Lorg/apache/commons/io/function/IOBaseStream;->onClose(Lorg/apache/commons/io/function/IORunnable;)Lorg/apache/commons/io/function/IOBaseStream;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Landroid/content/Context;

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dp9;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-static {}, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->getAllOp()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    invoke-static {v2}, Llyiahf/vczjk/os9;->OoooOOo(I)Llyiahf/vczjk/ze6;

    move-result-object v3

    if-eqz v3, :cond_0

    sget-object v4, Llyiahf/vczjk/ze6;->OooO0Oo:Llyiahf/vczjk/ze6;

    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-virtual {v1, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/oc6;

    if-nez v4, :cond_1

    new-instance v4, Llyiahf/vczjk/oc6;

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-direct {v4, v3, v5}, Llyiahf/vczjk/oc6;-><init>(Llyiahf/vczjk/ze6;Ljava/util/ArrayList;)V

    :cond_1
    invoke-static {p1, v2}, Llyiahf/vczjk/os9;->Oooo0oO(Landroid/content/Context;I)Ljava/lang/String;

    move-result-object v5

    invoke-static {p1, v2}, Llyiahf/vczjk/os9;->Oooo0oo(Landroid/content/Context;I)Ljava/lang/String;

    move-result-object v6

    invoke-static {p1, v2}, Llyiahf/vczjk/os9;->Oooo0o(Landroid/content/Context;I)I

    move-result v7

    new-instance v8, Lgithub/tornaco/thanos/android/ops/model/Op;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    iput-object v5, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOO0:Ljava/lang/String;

    iput-object v6, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOO:Ljava/lang/String;

    iput v7, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOOO:I

    iput v2, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOOo:I

    const/4 v2, 0x0

    iput v2, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOo0:I

    iput-boolean v2, v8, Lgithub/tornaco/thanos/android/ops/model/Op;->OooOOo:Z

    iget-object v2, v4, Llyiahf/vczjk/oc6;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v1, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/oc6;

    invoke-virtual {v1}, Llyiahf/vczjk/oc6;->OooO00o()Z

    move-result v2

    if-nez v2, :cond_3

    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    invoke-static {p1}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    return-object p1

    :pswitch_data_0
    .packed-switch 0x13
        :pswitch_0
    .end packed-switch
.end method

.method public apply(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, [B

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    check-cast p3, Ljava/lang/Integer;

    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    move-result p3

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/io/RandomAccessFile;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/RandomAccessFile;->read([BII)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public get()Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    sparse-switch v0, :sswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/UncheckedFilterReader$Builder;

    invoke-static {v0}, Lorg/apache/commons/io/input/UncheckedFilterReader$Builder;->OooO0O0(Lorg/apache/commons/io/input/UncheckedFilterReader$Builder;)Lorg/apache/commons/io/input/UncheckedFilterReader;

    move-result-object v0

    return-object v0

    :sswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/UncheckedFilterInputStream$Builder;

    invoke-static {v0}, Lorg/apache/commons/io/input/UncheckedFilterInputStream$Builder;->OooO0O0(Lorg/apache/commons/io/input/UncheckedFilterInputStream$Builder;)Lorg/apache/commons/io/input/UncheckedFilterInputStream;

    move-result-object v0

    return-object v0

    :sswitch_1
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/UncheckedBufferedReader$Builder;

    invoke-static {v0}, Lorg/apache/commons/io/input/UncheckedBufferedReader$Builder;->OooO0O0(Lorg/apache/commons/io/input/UncheckedBufferedReader$Builder;)Lorg/apache/commons/io/input/UncheckedBufferedReader;

    move-result-object v0

    return-object v0

    :sswitch_2
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lorg/apache/commons/io/input/SequenceReader;

    invoke-static {v0}, Lorg/apache/commons/io/input/SequenceReader;->OooO0Oo(Lorg/apache/commons/io/input/SequenceReader;)Ljava/io/Reader;

    move-result-object v0

    return-object v0

    nop

    :sswitch_data_0
    .sparse-switch
        0x8 -> :sswitch_2
        0x14 -> :sswitch_1
        0x15 -> :sswitch_0
    .end sparse-switch
.end method

.method public run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f0;

    invoke-virtual {v0}, Llyiahf/vczjk/f0;->run()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/td9;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/td9;->OooO0oO:Z

    invoke-virtual {v0}, Llyiahf/vczjk/td9;->OooOO0O()V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Runnable;

    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    return-void

    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public test(Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/n36;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uv6;

    iget-object v0, v0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOo0:Lnow/fortuitous/app/OooO00o;

    invoke-virtual {v0}, Lnow/fortuitous/app/OooO00o;->getCurrentFrontPkg()Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    invoke-static {v0, p1}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    return p1

    :pswitch_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getId()Ljava/lang/String;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/n36;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 p1, 0x0

    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method
