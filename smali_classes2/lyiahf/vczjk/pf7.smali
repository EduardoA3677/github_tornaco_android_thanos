.class public abstract Llyiahf/vczjk/pf7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "com.igexin.sdk.GActivity"

    const-string v1, ""

    filled-new-array {v0, v1}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/pf7;->OooO00o:Ljava/util/List;

    return-void
.end method

.method public static OooO00o(Landroid/content/Context;Landroid/content/ComponentName;)Z
    .locals 3

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Landroid/content/pm/PackageManager;->getActivityInfo(Landroid/content/ComponentName;I)Landroid/content/pm/ActivityInfo;

    move-result-object p0

    if-nez p0, :cond_0

    const-string p0, "PushSdkVendors, maybePushActivity return false since activityInfo is null."

    invoke-static {p0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    return v0

    :cond_0
    iget-object v1, p0, Landroid/content/pm/ActivityInfo;->processName:Ljava/lang/String;

    invoke-virtual {p1}, Landroid/content/ComponentName;->getPackageName()Ljava/lang/String;

    move-result-object p1

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    iget p0, p0, Landroid/content/pm/ActivityInfo;->flags:I

    and-int/lit8 p0, p0, 0x20

    const/4 v1, 0x1

    if-eqz p0, :cond_1

    move p0, v1

    goto :goto_0

    :cond_1
    move p0, v0

    :goto_0
    sget-object v2, Llyiahf/vczjk/he0;->OooO00o:Llyiahf/vczjk/fo9;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz p0, :cond_2

    if-nez p1, :cond_2

    return v1

    :cond_2
    return v0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-nez p1, :cond_3

    goto :goto_1

    :cond_3
    const-string p0, "PushSdkVendors, maybePushActivity error"

    invoke-static {p0, p1}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_1
    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0
.end method
