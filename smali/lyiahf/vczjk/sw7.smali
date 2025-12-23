.class public final Llyiahf/vczjk/sw7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/he5;
.implements Llyiahf/vczjk/pi;
.implements Llyiahf/vczjk/nm1;
.implements Llyiahf/vczjk/uw;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/ec9;
.implements Llyiahf/vczjk/u96;
.implements Llyiahf/vczjk/fh3;
.implements Llyiahf/vczjk/sx8;
.implements Llyiahf/vczjk/fp1;
.implements Llyiahf/vczjk/dh6;
.implements Llyiahf/vczjk/rd1;
.implements Lgithub/tornaco/android/thanos/core/profile/handle/IPower;


# static fields
.field public static OooOOOO:Ljava/lang/Class;

.field public static OooOOOo:Z

.field public static OooOOo:Z

.field public static OooOOo0:Ljava/lang/reflect/Method;

.field public static OooOOoo:Ljava/lang/reflect/Method;

.field public static OooOo00:Z


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    sparse-switch p1, :sswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object p1, Ljava/util/Locale;->CHINESE:Ljava/util/Locale;

    invoke-static {p1}, Ljava/text/Collator;->getInstance(Ljava/util/Locale;)Ljava/text/Collator;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/bua;->OooOOOO(Landroid/os/Looper;)Landroid/os/Handler;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_2
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_3
    sget-object p1, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    const-string v0, "timeUnit"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/rh7;

    sget-object v0, Llyiahf/vczjk/vg9;->OooO0oo:Llyiahf/vczjk/vg9;

    invoke-direct {p1, v0}, Llyiahf/vczjk/rh7;-><init>(Llyiahf/vczjk/vg9;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0xb -> :sswitch_3
        0xc -> :sswitch_2
        0xd -> :sswitch_1
        0x13 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/16 v0, 0x18

    iput v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/widget/TextView;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/hm2;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hm2;-><init>(Landroid/widget/TextView;)V

    iput-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/absinthe/rulesbundle/RuleDatabase_Impl;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/m62;

    const/4 v1, 0x2

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/m62;-><init>(Llyiahf/vczjk/ru7;I)V

    new-instance v0, Llyiahf/vczjk/qw7;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/qw7;-><init>(Llyiahf/vczjk/ru7;I)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ii7;Llyiahf/vczjk/a27;)V
    .locals 0

    const/16 p2, 0x17

    iput p2, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tr4;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    const-string v0, "packageFragment"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Z)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public static OooO0oo()V
    .locals 3

    sget-boolean v0, Llyiahf/vczjk/sw7;->OooOOOo:Z

    if-nez v0, :cond_0

    :try_start_0
    const-string v0, "android.view.GhostView"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/sw7;->OooOOOO:Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    const-string v1, "GhostViewApi21"

    const-string v2, "Failed to retrieve GhostView class"

    invoke-static {v1, v2, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_0
    const/4 v0, 0x1

    sput-boolean v0, Llyiahf/vczjk/sw7;->OooOOOo:Z

    :cond_0
    return-void
.end method

.method public static OooOOOO(Llyiahf/vczjk/li7;Llyiahf/vczjk/kv3;Lcoil/memory/MemoryCache$Key;Llyiahf/vczjk/ng5;)Llyiahf/vczjk/l99;
    .locals 8

    new-instance v0, Llyiahf/vczjk/l99;

    iget-object v1, p3, Llyiahf/vczjk/ng5;->OooO00o:Landroid/graphics/Bitmap;

    iget-object v2, p1, Llyiahf/vczjk/kv3;->OooO00o:Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v2

    move-object v3, v1

    new-instance v1, Landroid/graphics/drawable/BitmapDrawable;

    invoke-direct {v1, v2, v3}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    sget-object v3, Llyiahf/vczjk/zx1;->OooOOO0:Llyiahf/vczjk/zx1;

    const-string v2, "coil#disk_cache_key"

    iget-object p3, p3, Llyiahf/vczjk/ng5;->OooO0O0:Ljava/util/Map;

    invoke-interface {p3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    instance-of v4, v2, Ljava/lang/String;

    const/4 v5, 0x0

    if-eqz v4, :cond_0

    check-cast v2, Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object v2, v5

    :goto_0
    const-string v4, "coil#is_sampled"

    invoke-interface {p3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    instance-of v4, p3, Ljava/lang/Boolean;

    if-eqz v4, :cond_1

    move-object v5, p3

    check-cast v5, Ljava/lang/Boolean;

    :cond_1
    const/4 p3, 0x0

    if-eqz v5, :cond_2

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    move v6, v4

    goto :goto_1

    :cond_2
    move v6, p3

    :goto_1
    sget-object v4, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    if-eqz p0, :cond_3

    iget-boolean p0, p0, Llyiahf/vczjk/li7;->OooO0oO:Z

    if-eqz p0, :cond_3

    const/4 p3, 0x1

    :cond_3
    move-object v4, p2

    move v7, p3

    move-object v5, v2

    move-object v2, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/l99;-><init>(Landroid/graphics/drawable/Drawable;Llyiahf/vczjk/kv3;Llyiahf/vczjk/zx1;Lcoil/memory/MemoryCache$Key;Ljava/lang/String;ZZ)V

    return-object v0
.end method

.method public static OooOOo0(III)Llyiahf/vczjk/sw7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/sw7;

    const/4 v1, 0x0

    invoke-static {p0, p1, v1, p2}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;->obtain(IIZI)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;

    move-result-object p0

    const/4 p1, 0x1

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/eh6;

    iget-object v0, v0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yn;->Oooo0O0(Llyiahf/vczjk/pm;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public OooO00o(Llyiahf/vczjk/qd2;)V
    .locals 0

    return-void
.end method

.method public OooO0O0(Ljava/util/List;)V
    .locals 9

    const-string v0, "result"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/oe6;

    const/4 v0, 0x3

    invoke-direct {v5, v0}, Llyiahf/vczjk/oe6;-><init>(I)V

    const/4 v3, 0x0

    const/4 v4, 0x0

    const-string v2, ""

    const/16 v6, 0x1e

    move-object v1, p1

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vr6;

    const-string v1, "pattern"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v0, Llyiahf/vczjk/vr6;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v3, v2, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v3, Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/yr6;

    iget-object v3, v3, Llyiahf/vczjk/yr6;->OooO00o:Llyiahf/vczjk/k59;

    sget-object v4, Llyiahf/vczjk/i59;->OooO00o:Llyiahf/vczjk/i59;

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    sget-object v6, Llyiahf/vczjk/j59;->OooO00o:Llyiahf/vczjk/j59;

    iget-object v7, v0, Llyiahf/vczjk/vr6;->OooO0o:Llyiahf/vczjk/s29;

    if-eqz v5, :cond_1

    :cond_0
    invoke-virtual {v7}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/yr6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/yr6;

    invoke-direct {v1, v6, p1}, Llyiahf/vczjk/yr6;-><init>(Llyiahf/vczjk/k59;Ljava/lang/String;)V

    invoke-virtual {v7, v0, v1}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_1
    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_4

    iget-object v2, v2, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/yr6;

    iget-object v2, v2, Llyiahf/vczjk/yr6;->OooO0O0:Ljava/lang/String;

    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    const/4 v3, 0x3

    const/4 v5, 0x0

    if-nez v2, :cond_3

    :cond_2
    invoke-virtual {v7}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/yr6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/yr6;

    const-string v2, ""

    invoke-direct {v1, v4, v2}, Llyiahf/vczjk/yr6;-><init>(Llyiahf/vczjk/k59;Ljava/lang/String;)V

    invoke-virtual {v7, p1, v1}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/tr6;

    invoke-direct {v1, v0, v5}, Llyiahf/vczjk/tr6;-><init>(Llyiahf/vczjk/vr6;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v5, v5, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :cond_3
    invoke-virtual {v7}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/yr6;

    sget-object v6, Llyiahf/vczjk/h59;->OooO00o:Llyiahf/vczjk/h59;

    iget-object v4, v4, Llyiahf/vczjk/yr6;->OooO0O0:Ljava/lang/String;

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v8, Llyiahf/vczjk/yr6;

    invoke-direct {v8, v6, v4}, Llyiahf/vczjk/yr6;-><init>(Llyiahf/vczjk/k59;Ljava/lang/String;)V

    invoke-virtual {v7, v2, v8}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/vr6;->OooO:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v1

    invoke-virtual {v1, p1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setLockPattern(Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/ur6;

    invoke-direct {v1, v0, v5}, Llyiahf/vczjk/ur6;-><init>(Llyiahf/vczjk/vr6;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v5, v5, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_4
    :goto_0
    return-void
.end method

.method public OooO0OO(Landroid/view/ViewGroup;Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public OooO0Oo(Llyiahf/vczjk/qd2;)V
    .locals 0

    return-void
.end method

.method public OooO0o()Llyiahf/vczjk/a0;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "initializers"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/a0;

    const/4 v2, 0x0

    new-array v2, v2, [Llyiahf/vczjk/fha;

    invoke-interface {v0, v2}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/fha;

    array-length v2, v0

    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/fha;

    invoke-direct {v1, v0}, Llyiahf/vczjk/a0;-><init>([Llyiahf/vczjk/fha;)V

    return-object v1
.end method

.method public OooO0o0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V
    .locals 2

    const-string v0, "clazz"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "initializer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/fha;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/fha;-><init>(Llyiahf/vczjk/gf4;Llyiahf/vczjk/oe3;)V

    invoke-interface {v0, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_0
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "A `initializer` with the same `clazz` has already been added: "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0x2e

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public OooO0oO()V
    .locals 17

    move-object/from16 v1, p0

    iget-object v0, v1, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    move-object v2, v0

    check-cast v2, Landroid/content/Context;

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getNotificationManager()Lgithub/tornaco/android/thanos/core/n/NotificationManager;

    move-result-object v3

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v4

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    const/4 v6, 0x0

    move v7, v6

    :goto_0
    const/16 v0, 0xa

    invoke-virtual {v3, v7, v0}, Lgithub/tornaco/android/thanos/core/n/NotificationManager;->getAllNotificationRecordsByPage(II)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_3

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v0

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "nrs size: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    sget-object v0, Lgithub/tornaco/android/thanos/core/util/GsonUtils;->GSON:Llyiahf/vczjk/nk3;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-static {v3, v4}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatForFileName(J)Ljava/lang/String;

    move-result-object v3

    const-string v4, "Thanox_Export_Notifications_"

    const-string v5, ".json"

    invoke-static {v4, v3, v5}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isQOrAbove()Z

    move-result v4

    const-string v5, "File saved to: "

    const-string v7, "getBytes(...)"

    if-eqz v4, :cond_1

    new-instance v4, Landroid/content/ContentValues;

    invoke-direct {v4}, Landroid/content/ContentValues;-><init>()V

    const-string v6, "_display_name"

    invoke-virtual {v4, v6, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v3, "mime_type"

    const-string v6, "application/json"

    invoke-virtual {v4, v3, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    const-string v3, "relative_path"

    sget-object v6, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;

    invoke-virtual {v4, v3, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v2}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v2

    const-string v3, "external"

    invoke-static {v3}, Landroid/provider/MediaStore$Files;->getContentUri(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v3

    invoke-virtual {v2, v3, v4}, Landroid/content/ContentResolver;->insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;

    move-result-object v3

    if-eqz v3, :cond_2

    invoke-virtual {v2, v3}, Landroid/content/ContentResolver;->openOutputStream(Landroid/net/Uri;)Ljava/io/OutputStream;

    move-result-object v2

    if-eqz v2, :cond_0

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v4, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-virtual {v0, v4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v0

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/io/OutputStream;->write([B)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v2}, Ljava/io/Closeable;->close()V

    goto :goto_1

    :catchall_0
    move-exception v0

    move-object v3, v0

    :try_start_1
    throw v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    invoke-static {v2, v3}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :cond_0
    :goto_1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    goto :goto_2

    :cond_1
    sget-object v2, Landroid/os/Environment;->DIRECTORY_DOWNLOADS:Ljava/lang/String;

    invoke-static {v2}, Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;

    move-result-object v2

    new-instance v4, Ljava/io/File;

    invoke-direct {v4, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    :try_start_2
    new-instance v2, Ljava/io/FileOutputStream;

    invoke-direct {v2, v4}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v3, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-virtual {v0, v3}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v0

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/io/FileOutputStream;->write([B)V

    invoke-virtual {v2}, Ljava/io/FileOutputStream;->close()V

    invoke-virtual {v4}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    goto :goto_2

    :catch_0
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v2

    const-string v3, "Failed to save file: "

    invoke-static {v3, v2}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    new-array v3, v6, [Ljava/lang/Object;

    invoke-static {v2, v3, v0}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    :cond_2
    :goto_2
    return-void

    :cond_3
    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :cond_4
    :goto_3
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_c

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    :try_start_3
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v4, v10}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v10

    new-instance v11, Lgithub/tornaco/android/thanox/module/notification/recorder/source/NR;

    const-string v12, ""

    if-eqz v10, :cond_5

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v10

    if-nez v10, :cond_6

    :cond_5
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v10

    if-nez v10, :cond_6

    move-object v10, v12

    :cond_6
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v13

    if-nez v13, :cond_7

    move-object v13, v12

    :cond_7
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v14

    invoke-static {v14, v15}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object v14

    if-nez v14, :cond_8

    move-object v14, v12

    :cond_8
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getTitle()Ljava/lang/String;

    move-result-object v15

    if-nez v15, :cond_9

    move-object v15, v12

    :cond_9
    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getContent()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_a

    move-object/from16 v16, v12

    :goto_4
    move-object v12, v10

    goto :goto_5

    :cond_a
    move-object/from16 v16, v0

    goto :goto_4

    :goto_5
    invoke-direct/range {v11 .. v16}, Lgithub/tornaco/android/thanox/module/notification/recorder/source/NR;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    goto :goto_6

    :catchall_2
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v11

    :goto_6
    instance-of v0, v11, Llyiahf/vczjk/ts7;

    if-eqz v0, :cond_b

    const/4 v11, 0x0

    :cond_b
    check-cast v11, Lgithub/tornaco/android/thanox/module/notification/recorder/source/NR;

    if-eqz v11, :cond_4

    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_c
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    add-int/lit8 v7, v7, 0xa

    goto/16 :goto_0
.end method

.method public OooOO0(Ljava/lang/Class;)Llyiahf/vczjk/cy8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cy8;

    return-object p1
.end method

.method public OooOO0O(Llyiahf/vczjk/kv3;Lcoil/memory/MemoryCache$Key;Llyiahf/vczjk/sq8;Llyiahf/vczjk/r78;)Llyiahf/vczjk/ng5;
    .locals 17

    move-object/from16 v0, p1

    move-object/from16 v1, p2

    move-object/from16 v2, p3

    iget-object v3, v0, Llyiahf/vczjk/kv3;->OooOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v3}, Llyiahf/vczjk/vm0;->OooO00o()Z

    move-result v3

    const/4 v4, 0x0

    if-nez v3, :cond_0

    move-object/from16 v3, p0

    goto/16 :goto_16

    :cond_0
    move-object/from16 v3, p0

    iget-object v5, v3, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/ii7;

    iget-object v5, v5, Llyiahf/vczjk/ii7;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v5}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/mi7;

    if-eqz v5, :cond_6

    iget-object v6, v5, Llyiahf/vczjk/mi7;->OooO00o:Llyiahf/vczjk/k79;

    invoke-interface {v6, v1}, Llyiahf/vczjk/k79;->Oooo0oO(Lcoil/memory/MemoryCache$Key;)Llyiahf/vczjk/ng5;

    move-result-object v6

    if-nez v6, :cond_7

    iget-object v5, v5, Llyiahf/vczjk/mi7;->OooO0O0:Llyiahf/vczjk/w3;

    monitor-enter v5

    :try_start_0
    iget-object v6, v5, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v6, Ljava/util/LinkedHashMap;

    invoke-virtual {v6, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/ArrayList;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v7, 0x0

    if-nez v6, :cond_1

    monitor-exit v5

    :goto_0
    move-object v6, v7

    goto :goto_5

    :cond_1
    :try_start_1
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v8

    const/4 v9, 0x0

    :goto_1
    if-ge v9, v8, :cond_4

    invoke-interface {v6, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/si7;

    iget-object v11, v10, Llyiahf/vczjk/si7;->OooO0O0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v11}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Landroid/graphics/Bitmap;

    if-eqz v11, :cond_2

    new-instance v12, Llyiahf/vczjk/ng5;

    iget-object v10, v10, Llyiahf/vczjk/si7;->OooO0OO:Ljava/util/Map;

    invoke-direct {v12, v11, v10}, Llyiahf/vczjk/ng5;-><init>(Landroid/graphics/Bitmap;Ljava/util/Map;)V

    goto :goto_2

    :catchall_0
    move-exception v0

    goto :goto_4

    :cond_2
    move-object v12, v7

    :goto_2
    if-eqz v12, :cond_3

    move-object v7, v12

    goto :goto_3

    :cond_3
    add-int/lit8 v9, v9, 0x1

    goto :goto_1

    :cond_4
    :goto_3
    iget v6, v5, Llyiahf/vczjk/w3;->OooOOO0:I

    add-int/lit8 v8, v6, 0x1

    iput v8, v5, Llyiahf/vczjk/w3;->OooOOO0:I

    const/16 v8, 0xa

    if-lt v6, v8, :cond_5

    invoke-virtual {v5}, Llyiahf/vczjk/w3;->OooO0OO()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_5
    monitor-exit v5

    goto :goto_0

    :goto_4
    :try_start_2
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw v0

    :cond_6
    move-object v6, v4

    :cond_7
    :goto_5
    if-eqz v6, :cond_1d

    iget-object v5, v6, Llyiahf/vczjk/ng5;->OooO00o:Landroid/graphics/Bitmap;

    invoke-virtual {v5}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    move-result-object v7

    if-nez v7, :cond_8

    sget-object v7, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    :cond_8
    invoke-static {v7}, Llyiahf/vczjk/rs;->Oooo0oo(Landroid/graphics/Bitmap$Config;)Z

    move-result v7

    if-nez v7, :cond_9

    goto :goto_6

    :cond_9
    iget-boolean v7, v0, Llyiahf/vczjk/kv3;->OooOO0O:Z

    if-nez v7, :cond_a

    const/4 v7, 0x0

    goto :goto_7

    :cond_a
    :goto_6
    const/4 v7, 0x1

    :goto_7
    if-nez v7, :cond_b

    :goto_8
    const/4 v8, 0x0

    goto/16 :goto_15

    :cond_b
    const-string v7, "coil#is_sampled"

    iget-object v10, v6, Llyiahf/vczjk/ng5;->OooO0O0:Ljava/util/Map;

    invoke-interface {v10, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    instance-of v10, v7, Ljava/lang/Boolean;

    if-eqz v10, :cond_c

    check-cast v7, Ljava/lang/Boolean;

    goto :goto_9

    :cond_c
    move-object v7, v4

    :goto_9
    if-eqz v7, :cond_d

    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    goto :goto_a

    :cond_d
    const/4 v7, 0x0

    :goto_a
    sget-object v10, Llyiahf/vczjk/sq8;->OooO0OO:Llyiahf/vczjk/sq8;

    invoke-static {v2, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_f

    if-eqz v7, :cond_e

    goto/16 :goto_13

    :cond_e
    :goto_b
    const/4 v9, 0x1

    goto/16 :goto_14

    :cond_f
    const-string v10, "coil#transformation_size"

    iget-object v1, v1, Lcoil/memory/MemoryCache$Key;->OooOOO:Ljava/util/Map;

    invoke-interface {v1, v10}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-eqz v1, :cond_10

    invoke-virtual {v2}, Llyiahf/vczjk/sq8;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    goto/16 :goto_15

    :cond_10
    invoke-virtual {v5}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v1

    invoke-virtual {v5}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v5

    iget-object v10, v2, Llyiahf/vczjk/sq8;->OooO00o:Llyiahf/vczjk/sb;

    instance-of v11, v10, Llyiahf/vczjk/ob2;

    const v12, 0x7fffffff

    if-eqz v11, :cond_11

    check-cast v10, Llyiahf/vczjk/ob2;

    iget v10, v10, Llyiahf/vczjk/ob2;->OooOO0:I

    goto :goto_c

    :cond_11
    move v10, v12

    :goto_c
    iget-object v2, v2, Llyiahf/vczjk/sq8;->OooO0O0:Llyiahf/vczjk/sb;

    instance-of v11, v2, Llyiahf/vczjk/ob2;

    if-eqz v11, :cond_12

    check-cast v2, Llyiahf/vczjk/ob2;

    iget v2, v2, Llyiahf/vczjk/ob2;->OooOO0:I

    :goto_d
    move-object/from16 v11, p4

    goto :goto_e

    :cond_12
    move v2, v12

    goto :goto_d

    :goto_e
    invoke-static {v1, v5, v10, v2, v11}, Llyiahf/vczjk/r02;->OooOO0o(IIIILlyiahf/vczjk/r78;)D

    move-result-wide v13

    invoke-static {v0}, Llyiahf/vczjk/OooOO0O;->OooO00o(Llyiahf/vczjk/kv3;)Z

    move-result v0

    const-wide/high16 v15, 0x3ff0000000000000L    # 1.0

    if-eqz v0, :cond_15

    cmpl-double v11, v13, v15

    if-lez v11, :cond_13

    move-wide v11, v15

    goto :goto_f

    :cond_13
    move-wide v11, v13

    :goto_f
    int-to-double v9, v10

    move-wide/from16 p1, v9

    int-to-double v8, v1

    mul-double/2addr v8, v11

    sub-double v9, p1, v8

    invoke-static {v9, v10}, Ljava/lang/Math;->abs(D)D

    move-result-wide v8

    cmpg-double v1, v8, v15

    if-lez v1, :cond_e

    int-to-double v1, v2

    int-to-double v8, v5

    mul-double/2addr v11, v8

    sub-double/2addr v1, v11

    invoke-static {v1, v2}, Ljava/lang/Math;->abs(D)D

    move-result-wide v1

    cmpg-double v1, v1, v15

    if-gtz v1, :cond_14

    goto :goto_b

    :cond_14
    const/4 v9, 0x1

    goto :goto_11

    :cond_15
    const/high16 v8, -0x80000000

    if-eq v10, v8, :cond_16

    if-ne v10, v12, :cond_17

    :cond_16
    const/4 v9, 0x1

    goto :goto_10

    :cond_17
    sub-int/2addr v10, v1

    invoke-static {v10}, Ljava/lang/Math;->abs(I)I

    move-result v1

    const/4 v9, 0x1

    if-gt v1, v9, :cond_19

    :goto_10
    if-eq v2, v8, :cond_1c

    if-ne v2, v12, :cond_18

    goto :goto_14

    :cond_18
    sub-int/2addr v2, v5

    invoke-static {v2}, Ljava/lang/Math;->abs(I)I

    move-result v1

    if-gt v1, v9, :cond_19

    goto :goto_14

    :cond_19
    :goto_11
    cmpg-double v1, v13, v15

    if-nez v1, :cond_1a

    goto :goto_12

    :cond_1a
    if-nez v0, :cond_1b

    goto :goto_13

    :cond_1b
    :goto_12
    cmpl-double v0, v13, v15

    if-lez v0, :cond_1c

    if-eqz v7, :cond_1c

    :goto_13
    goto/16 :goto_8

    :cond_1c
    :goto_14
    move v8, v9

    :goto_15
    if-eqz v8, :cond_1d

    return-object v6

    :cond_1d
    :goto_16
    return-object v4
.end method

.method public OooOO0o(Llyiahf/vczjk/hj1;)I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t92;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v1, p1, Llyiahf/vczjk/zt1;

    const-string v2, "not found"

    const-string v3, "cst == null"

    if-eqz v1, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/t92;->OooO0o0:Llyiahf/vczjk/ce7;

    if-eqz p1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v0, v0, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Ljava/util/TreeMap;

    invoke-virtual {v0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gx3;

    if-eqz p1, :cond_0

    goto/16 :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/NullPointerException;

    invoke-direct {p1, v3}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    instance-of v1, p1, Llyiahf/vczjk/au1;

    if-eqz v1, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/t92;->OooO0o:Llyiahf/vczjk/ce7;

    if-eqz p1, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/au1;

    iget-object v0, v0, Llyiahf/vczjk/ce7;->OooO0oO:Ljava/lang/Object;

    check-cast v0, Ljava/util/TreeMap;

    iget-object v1, v1, Llyiahf/vczjk/au1;->OooOOO0:Llyiahf/vczjk/p1a;

    invoke-virtual {v0, v1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/gx3;

    if-eqz v0, :cond_3

    move-object p1, v0

    goto :goto_0

    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const-string v1, "not found: "

    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/NullPointerException;

    invoke-direct {p1, v3}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    instance-of v1, p1, Llyiahf/vczjk/wt1;

    if-eqz v1, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/t92;->OooO:Llyiahf/vczjk/bj5;

    if-eqz p1, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v0, v0, Llyiahf/vczjk/bj5;->OooO0o:Ljava/util/TreeMap;

    invoke-virtual {v0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gx3;

    if-eqz p1, :cond_6

    goto :goto_0

    :cond_6
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/NullPointerException;

    invoke-direct {p1, v3}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    instance-of v1, p1, Llyiahf/vczjk/lt1;

    if-eqz v1, :cond_b

    iget-object v0, v0, Llyiahf/vczjk/t92;->OooO0oo:Llyiahf/vczjk/ix2;

    if-eqz p1, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/bc8;->OooO0o()V

    iget-object v0, v0, Llyiahf/vczjk/ix2;->OooO0o:Ljava/util/TreeMap;

    invoke-virtual {v0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gx3;

    if-eqz p1, :cond_9

    goto :goto_0

    :cond_9
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_a
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/NullPointerException;

    invoke-direct {p1, v3}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_b
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_c

    const/4 p1, -0x1

    return p1

    :cond_c
    invoke-virtual {p1}, Llyiahf/vczjk/gx3;->OooO0o0()I

    move-result p1

    return p1
.end method

.method public OooOOO(Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;)Lcoil/memory/MemoryCache$Key;
    .locals 6

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p4, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast p4, Llyiahf/vczjk/ii7;

    iget-object p4, p4, Llyiahf/vczjk/ii7;->OooO0oO:Llyiahf/vczjk/f71;

    iget-object p4, p4, Llyiahf/vczjk/f71;->OooO0OO:Ljava/util/List;

    invoke-interface {p4}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    const/4 v2, 0x0

    if-ge v1, v0, :cond_1

    invoke-interface {p4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xn6;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/oj4;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_0

    const-string v3, "null cannot be cast to non-null type coil.key.Keyer<kotlin.Any>"

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4, p2, p3}, Llyiahf/vczjk/oj4;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/hf6;)Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    move-object v3, v2

    :goto_1
    if-nez v3, :cond_2

    return-object v2

    :cond_2
    iget-object p2, p1, Llyiahf/vczjk/kv3;->OooOo:Llyiahf/vczjk/ap6;

    iget-object p2, p2, Llyiahf/vczjk/ap6;->OooOOO0:Ljava/util/Map;

    invoke-interface {p2}, Ljava/util/Map;->isEmpty()Z

    move-result p3

    sget-object p4, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    if-eqz p3, :cond_3

    move-object p3, p4

    goto :goto_2

    :cond_3
    new-instance p3, Ljava/util/LinkedHashMap;

    invoke-direct {p3}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_5

    :goto_2
    iget-object p1, p1, Llyiahf/vczjk/kv3;->OooO0o:Llyiahf/vczjk/an2;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {p3}, Ljava/util/Map;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_4

    new-instance p1, Lcoil/memory/MemoryCache$Key;

    invoke-direct {p1, v3, p4}, Lcoil/memory/MemoryCache$Key;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    return-object p1

    :cond_4
    invoke-static {p3}, Llyiahf/vczjk/lc5;->oo0o0Oo(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object p1

    new-instance p2, Lcoil/memory/MemoryCache$Key;

    invoke-direct {p2, v3, p1}, Lcoil/memory/MemoryCache$Key;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    return-object p2

    :cond_5
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map$Entry;

    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

.method public OooOOO0()Ljava/lang/StringBuilder;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/o0OOO0o;

    instance-of v1, v0, Llyiahf/vczjk/go6;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/go6;

    iget-object v0, v0, Llyiahf/vczjk/go6;->OooO0O0:Llyiahf/vczjk/g05;

    iget-object v0, v0, Llyiahf/vczjk/g05;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public OooOOOo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/common/CommonFuncToggleAppListFilterActivity;

    iget-object v0, v0, Lgithub/tornaco/android/thanos/common/BaseAppListFilterActivity;->Oooo0oO:Llyiahf/vczjk/t41;

    check-cast v0, Llyiahf/vczjk/g51;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/t41;->OooO0o(Z)V

    return-void
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;

    iget-boolean v0, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOO0:Z

    if-nez v0, :cond_0

    iget-boolean v0, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOOO:Z

    if-nez v0, :cond_0

    iget-boolean v0, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOO:Z

    if-nez v0, :cond_0

    iget-boolean v0, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOOo:Z

    if-nez v0, :cond_0

    return-object p2

    :cond_0
    iget-object v0, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v1, 0x28f

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v0

    iget v1, v0, Llyiahf/vczjk/x04;->OooO0Oo:I

    iput v1, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOo:I

    iget v1, v0, Llyiahf/vczjk/x04;->OooO0O0:I

    iput v1, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOOoo:I

    iget v1, v0, Llyiahf/vczjk/x04;->OooO0OO:I

    iput v1, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOo0:I

    iget v0, v0, Llyiahf/vczjk/x04;->OooO00o:I

    iput v0, p1, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooOo00:I

    invoke-virtual {p1}, Lcom/google/android/material/floatingtoolbar/FloatingToolbarLayout;->OooO00o()V

    return-object p2
.end method

.method public Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x16

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    new-instance v0, Llyiahf/vczjk/tw;

    invoke-direct {v0, p1, p0}, Llyiahf/vczjk/tw;-><init>(Llyiahf/vczjk/h93;Llyiahf/vczjk/sw7;)V

    return-object v0
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 4

    check-cast p1, Llyiahf/vczjk/wu;

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t41;

    iget-object v1, v0, Llyiahf/vczjk/t41;->OooO0oo:Landroidx/databinding/ObservableField;

    invoke-virtual {v1}, Landroidx/databinding/ObservableField;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sw;

    if-eqz v1, :cond_1

    iget-object v1, v1, Llyiahf/vczjk/sw;->provider:Llyiahf/vczjk/rw;

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v2

    invoke-interface {v1, v2, p1}, Llyiahf/vczjk/rw;->OooOOoo(Landroid/app/Application;Llyiahf/vczjk/wu;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v3, p1, Llyiahf/vczjk/wu;->OooOOo0:Ljava/lang/String;

    if-nez v3, :cond_0

    const-string v3, ""

    :cond_0
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\n"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v1

    iput-object v1, p1, Llyiahf/vczjk/wu;->OooOOo0:Ljava/lang/String;

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/t41;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public convert(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ks7;

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fp1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/fp1;->convert(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1}, Ljava/util/Optional;->ofNullable(Ljava/lang/Object;)Ljava/util/Optional;

    move-result-object p1

    return-object p1
.end method

.method public getBrightness()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0}, Llyiahf/vczjk/k07;->getBrightness()I

    move-result v0

    return v0
.end method

.method public isAutoBrightnessEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0}, Llyiahf/vczjk/k07;->isAutoBrightnessEnabled()Z

    move-result v0

    return v0
.end method

.method public o000000()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    return-object v0
.end method

.method public o000000o()Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ne v1, v3, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pj4;

    invoke-virtual {v0}, Llyiahf/vczjk/pj4;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_0

    return v3

    :cond_0
    return v2
.end method

.method public o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "model"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public o0OOO0o()Llyiahf/vczjk/d80;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pj4;

    invoke-virtual {v1}, Llyiahf/vczjk/pj4;->OooO0OO()Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/xi3;

    const/4 v2, 0x1

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/xi3;-><init>(ILjava/util/List;)V

    return-object v1

    :cond_0
    new-instance v1, Llyiahf/vczjk/fq6;

    invoke-direct {v1, v0}, Llyiahf/vczjk/fq6;-><init>(Ljava/util/ArrayList;)V

    return-object v1
.end method

.method public onQueryTextChange(Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    iget v1, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    const-string v1, "newText"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OoooO00:I

    check-cast v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OooOoOO()Llyiahf/vczjk/l46;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/l46;->OooO0o0(Ljava/lang/String;)V

    return-void

    :pswitch_0
    check-cast v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;

    iget-object v0, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;->Oooo0oo:Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;

    iget-object v1, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o:Landroidx/databinding/ObservableField;

    invoke-virtual {v1, p1}, Landroidx/databinding/ObservableField;->set(Ljava/lang/Object;)V

    iget-object p1, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    invoke-virtual {v0}, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o()V

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public onQueryTextSubmit(Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    iget v1, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    const-string v1, "query"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OoooO00:I

    check-cast v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OooOoOO()Llyiahf/vczjk/l46;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/l46;->OooO0o0(Ljava/lang/String;)V

    return-void

    :pswitch_0
    check-cast v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;

    iget-object v0, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/ActivityTrampolineActivity;->Oooo0oo:Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;

    iget-object v1, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o:Landroidx/databinding/ObservableField;

    invoke-virtual {v1, p1}, Landroidx/databinding/ObservableField;->set(Ljava/lang/Object;)V

    iget-object p1, v0, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    invoke-virtual {v0}, Lgithub/tornaco/android/thanox/module/activity/trampoline/OooO00o;->OooO0o()V

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public setAutoBrightnessEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k07;->setAutoBrightnessEnabled(Z)V

    return-void
.end method

.method public setBrightness(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k07;->setBrightness(I)V

    return-void
.end method

.method public setVisibility(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0, p1}, Landroid/view/View;->setVisibility(I)V

    return-void
.end method

.method public sleep(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/k07;->goToSleep(J)V

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/sw7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tr4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ": "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, v1, Llyiahf/vczjk/tr4;->OooOo:Llyiahf/vczjk/o45;

    sget-object v2, Llyiahf/vczjk/tr4;->OooOoo0:[Llyiahf/vczjk/th4;

    const/4 v3, 0x0

    aget-object v2, v2, v3

    invoke-static {v1, v2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map;

    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x14
        :pswitch_0
    .end packed-switch
.end method

.method public wakeup(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/k07;->wakeUp(J)V

    return-void
.end method
