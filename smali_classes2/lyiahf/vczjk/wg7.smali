.class public final Llyiahf/vczjk/wg7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nk4;
.implements Llyiahf/vczjk/lb2;
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/s17;
.implements Llyiahf/vczjk/k48;
.implements Llyiahf/vczjk/em;


# instance fields
.field public final OooOOO0:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(FF)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/b33;

    const v1, 0x3c23d70a    # 0.01f

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/b33;-><init>(FFF)V

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/content/pm/ShortcutInfo;)V
    .locals 12

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/an8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO00o:Landroid/content/Context;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOo0o(Landroid/content/pm/ShortcutInfo;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0O0:Ljava/lang/String;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOOo(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOo00(Landroid/content/pm/ShortcutInfo;)[Landroid/content/Intent;

    move-result-object p1

    array-length v1, p1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Landroid/content/Intent;

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0OO:[Landroid/content/Intent;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO0O0(Landroid/content/pm/ShortcutInfo;)Landroid/content/ComponentName;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0Oo:Landroid/content/ComponentName;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO0oo(Landroid/content/pm/ShortcutInfo;)Ljava/lang/CharSequence;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0o0:Ljava/lang/CharSequence;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOo0O(Landroid/content/pm/ShortcutInfo;)Ljava/lang/CharSequence;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0o:Ljava/lang/CharSequence;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOoO(Landroid/content/pm/ShortcutInfo;)Ljava/lang/CharSequence;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooO0oO:Ljava/lang/CharSequence;

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt p1, v1, :cond_0

    invoke-static {p2}, Llyiahf/vczjk/a32;->OooOOOO(Landroid/content/pm/ShortcutInfo;)V

    goto :goto_0

    :cond_0
    invoke-static {p2}, Llyiahf/vczjk/zm8;->OooOO0(Landroid/content/pm/ShortcutInfo;)V

    :goto_0
    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOO0(Landroid/content/pm/ShortcutInfo;)Ljava/util/Set;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/an8;->OooOO0:Ljava/util/Set;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO0oO(Landroid/content/pm/ShortcutInfo;)Landroid/os/PersistableBundle;

    move-result-object p1

    const/4 v1, 0x0

    if-eqz p1, :cond_2

    const-string v2, "extraPersonCount"

    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_2

    :cond_1
    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    move-result v2

    new-array v3, v2, [Llyiahf/vczjk/gt6;

    const/4 v4, 0x0

    :goto_1
    if-ge v4, v2, :cond_3

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "extraPerson_"

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    add-int/lit8 v6, v4, 0x1

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p1, v5}, Landroid/os/PersistableBundle;->getPersistableBundle(Ljava/lang/String;)Landroid/os/PersistableBundle;

    move-result-object v5

    const-string v7, "name"

    invoke-virtual {v5, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    const-string v8, "uri"

    invoke-virtual {v5, v8}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    const-string v9, "key"

    invoke-virtual {v5, v9}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    const-string v10, "isBot"

    invoke-virtual {v5, v10}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    move-result v10

    const-string v11, "isImportant"

    invoke-virtual {v5, v11}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    move-result v5

    new-instance v11, Llyiahf/vczjk/gt6;

    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    iput-object v7, v11, Llyiahf/vczjk/gt6;->OooO00o:Ljava/lang/String;

    iput-object v8, v11, Llyiahf/vczjk/gt6;->OooO0O0:Ljava/lang/String;

    iput-object v9, v11, Llyiahf/vczjk/gt6;->OooO0OO:Ljava/lang/String;

    iput-boolean v10, v11, Llyiahf/vczjk/gt6;->OooO0Oo:Z

    iput-boolean v5, v11, Llyiahf/vczjk/gt6;->OooO0o0:Z

    aput-object v11, v3, v4

    move v4, v6

    goto :goto_1

    :cond_2
    :goto_2
    move-object v3, v1

    :cond_3
    iput-object v3, v0, Llyiahf/vczjk/an8;->OooO:[Llyiahf/vczjk/gt6;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOoO0(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOoOO(Landroid/content/pm/ShortcutInfo;)V

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1e

    if-lt p1, v0, :cond_4

    invoke-static {p2}, Llyiahf/vczjk/o0O0OOO0;->OooOOO(Landroid/content/pm/ShortcutInfo;)V

    :cond_4
    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOoo0(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOoo(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooOooO(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/zm8;->OooO0o(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/zm8;->OooOO0(Landroid/content/pm/ShortcutInfo;)V

    invoke-static {p2}, Llyiahf/vczjk/zm8;->OooOO0o(Landroid/content/pm/ShortcutInfo;)V

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/an8;

    const/16 v2, 0x1d

    if-lt p1, v2, :cond_7

    invoke-static {p2}, Llyiahf/vczjk/hp7;->OooO0oO(Landroid/content/pm/ShortcutInfo;)Landroid/content/LocusId;

    move-result-object p1

    if-nez p1, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {p2}, Llyiahf/vczjk/hp7;->OooO0oO(Landroid/content/pm/ShortcutInfo;)Landroid/content/LocusId;

    move-result-object p1

    const-string v1, "locusId cannot be null"

    invoke-static {p1, v1}, Llyiahf/vczjk/br6;->OooOOO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/v45;

    invoke-static {p1}, Llyiahf/vczjk/xo;->OooO0OO(Landroid/content/LocusId;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_6

    invoke-direct {v1, p1}, Llyiahf/vczjk/v45;-><init>(Ljava/lang/String;)V

    goto :goto_3

    :cond_6
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "id cannot be empty"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_7
    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO0oO(Landroid/content/pm/ShortcutInfo;)Landroid/os/PersistableBundle;

    move-result-object p1

    if-nez p1, :cond_8

    goto :goto_3

    :cond_8
    const-string v2, "extraLocusId"

    invoke-virtual {p1, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-nez p1, :cond_9

    goto :goto_3

    :cond_9
    new-instance v1, Llyiahf/vczjk/v45;

    invoke-direct {v1, p1}, Llyiahf/vczjk/v45;-><init>(Ljava/lang/String;)V

    :goto_3
    iput-object v1, v0, Llyiahf/vczjk/an8;->OooOO0O:Llyiahf/vczjk/v45;

    iget-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/an8;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO00o(Landroid/content/pm/ShortcutInfo;)I

    move-result v0

    iput v0, p1, Llyiahf/vczjk/an8;->OooOO0o:I

    iget-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/an8;

    invoke-static {p2}, Llyiahf/vczjk/al2;->OooO0oO(Landroid/content/pm/ShortcutInfo;)Landroid/os/PersistableBundle;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/an8;->OooOOO0:Landroid/os/PersistableBundle;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1e

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/fx8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gv7;-><init>(Ljava/lang/Object;)V

    iput-object p1, v0, Llyiahf/vczjk/fx8;->OooOOO:Landroid/view/View;

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void

    :cond_0
    new-instance v0, Llyiahf/vczjk/gv7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gv7;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsetsController;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/fx8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/gv7;-><init>(Ljava/lang/Object;)V

    iput-object p1, v0, Llyiahf/vczjk/fx8;->OooOOOO:Landroid/view/WindowInsetsController;

    iput-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ea9;)V
    .locals 1

    const-string v0, "openHelper"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/oOO0O00O;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    return-void
.end method

.method public OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/j48;
    .locals 1

    const-string v0, "fileName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/aa9;

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ea9;

    invoke-interface {v0}, Llyiahf/vczjk/ea9;->OoooOOO()Llyiahf/vczjk/ca9;

    move-result-object v0

    invoke-direct {p1, v0}, Llyiahf/vczjk/aa9;-><init>(Llyiahf/vczjk/ca9;)V

    return-object p1
.end method

.method public OooO0o0(Ljava/lang/Object;)V
    .locals 1

    :try_start_0
    check-cast p1, Ljava/util/List;

    invoke-static {p1}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    const-string v0, "The mapper function returned a null value."

    invoke-static {p1, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/wg7;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooOO0(Ljava/io/Serializable;)Z
    .locals 1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->setSmartStandByByPassIfHasNotificationEnabled(Z)V

    const/4 p1, 0x1

    return p1
.end method

.method public OooOOO(F)Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OooOoO:Landroidx/recyclerview/widget/OooOo00;

    invoke-virtual {v1}, Landroidx/recyclerview/widget/OooOo00;->OooO0o()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    float-to-int p1, p1

    move v1, p1

    move p1, v2

    goto :goto_0

    :cond_0
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OooOoO:Landroidx/recyclerview/widget/OooOo00;

    invoke-virtual {v1}, Landroidx/recyclerview/widget/OooOo00;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_1

    float-to-int p1, p1

    move v1, v2

    goto :goto_0

    :cond_1
    move p1, v2

    move v1, p1

    :goto_0
    if-nez p1, :cond_2

    if-nez v1, :cond_2

    return v2

    :cond_2
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->oo000o()V

    const v3, 0x7fffffff

    invoke-virtual {v0, p1, v1, v2, v3}, Landroidx/recyclerview/widget/RecyclerView;->Oooo0o0(IIII)Z

    move-result p1

    return p1
.end method

.method public OooOOOO()V
    .locals 0

    return-void
.end method

.method public OooOOOo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/ok4;
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    const-string v0, "d1"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance p1, Llyiahf/vczjk/vg7;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/vg7;-><init>(Llyiahf/vczjk/nk4;I)V

    return-object p1

    :cond_0
    const-string v0, "d2"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/vg7;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/vg7;-><init>(Llyiahf/vczjk/nk4;I)V

    return-object p1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOOo(Llyiahf/vczjk/qt5;Ljava/lang/Object;)V
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p1

    const-string v0, "k"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/yg7;

    if-eqz v0, :cond_1

    instance-of p1, p2, Ljava/lang/Integer;

    if-eqz p1, :cond_5

    check-cast p2, Ljava/lang/Integer;

    sget-object p1, Llyiahf/vczjk/ik4;->OooOOO0:Llyiahf/vczjk/ws7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/ik4;->OooOOO:Ljava/util/LinkedHashMap;

    invoke-virtual {p1, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ik4;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/ik4;->OooOOOO:Llyiahf/vczjk/ik4;

    :cond_0
    iput-object p1, v1, Llyiahf/vczjk/yg7;->OooO0oO:Llyiahf/vczjk/ik4;

    return-void

    :cond_1
    const-string v0, "mv"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    instance-of p1, p2, [I

    if-eqz p1, :cond_5

    check-cast p2, [I

    iput-object p2, v1, Llyiahf/vczjk/yg7;->OooO00o:[I

    return-void

    :cond_2
    const-string v0, "xs"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    instance-of p1, p2, Ljava/lang/String;

    if-eqz p1, :cond_5

    check-cast p2, Ljava/lang/String;

    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result p1

    if-nez p1, :cond_5

    iput-object p2, v1, Llyiahf/vczjk/yg7;->OooO0O0:Ljava/lang/String;

    return-void

    :cond_3
    const-string v0, "xi"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    instance-of p1, p2, Ljava/lang/Integer;

    if-eqz p1, :cond_5

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p1

    iput p1, v1, Llyiahf/vczjk/yg7;->OooO0OO:I

    return-void

    :cond_4
    const-string v0, "pn"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_5

    instance-of p1, p2, Ljava/lang/String;

    if-eqz p1, :cond_5

    check-cast p2, Ljava/lang/String;

    invoke-virtual {p2}, Ljava/lang/String;->isEmpty()Z

    move-result p1

    if-nez p1, :cond_5

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_5
    return-void
.end method

.method public OooOOo0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)V
    .locals 0

    return-void
.end method

.method public OooOo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->oo000o()V

    return-void
.end method

.method public OooOo0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/my0;)V
    .locals 0

    return-void
.end method

.method public OooOo00(Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)Llyiahf/vczjk/nk4;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOo0o()F
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OooOoO:Landroidx/recyclerview/widget/OooOo00;

    invoke-virtual {v1}, Landroidx/recyclerview/widget/OooOo00;->OooO0o()Z

    move-result v1

    if-eqz v1, :cond_0

    iget v0, v0, Landroidx/recyclerview/widget/RecyclerView;->ooOO:F

    :goto_0
    neg-float v0, v0

    return v0

    :cond_0
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OooOoO:Landroidx/recyclerview/widget/OooOo00;

    invoke-virtual {v1}, Landroidx/recyclerview/widget/OooOo00;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_1

    iget v0, v0, Landroidx/recyclerview/widget/RecyclerView;->o0OoOo0:F

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public get(I)Llyiahf/vczjk/t23;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/b33;

    return-object p1
.end method
