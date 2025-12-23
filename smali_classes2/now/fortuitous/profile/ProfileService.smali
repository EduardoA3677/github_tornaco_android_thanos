.class public final Lnow/fortuitous/profile/ProfileService;
.super Llyiahf/vczjk/aq9;
.source "SourceFile"

# interfaces
.implements Lgithub/tornaco/android/thanos/core/profile/IProfileManager;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u00012\u00020\u0002J5\u0010\u000c\u001a\u00020\u000b2\u0006\u0010\u0004\u001a\u00020\u00032\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0008\u001a\u00020\u00072\n\u0010\n\u001a\u0006\u0012\u0002\u0008\u00030\tH\u0007\u00a2\u0006\u0004\u0008\u000c\u0010\r\u00a8\u0006\u000e"
    }
    d2 = {
        "Lnow/fortuitous/profile/ProfileService;",
        "Llyiahf/vczjk/aq9;",
        "Lgithub/tornaco/android/thanos/core/profile/IProfileManager;",
        "",
        "source",
        "",
        "factValue",
        "",
        "delayMills",
        "",
        "args",
        "Llyiahf/vczjk/z8a;",
        "publishStringFactInternal",
        "(ILjava/lang/String;J[Ljava/lang/Object;)V",
        "services"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooOO0:Llyiahf/vczjk/up3;

.field public OooOO0O:Z

.field public OooOO0o:Z

.field public OooOOO:Z

.field public OooOOO0:Ljava/lang/String;

.field public OooOOOO:Z

.field public OooOOOo:Z

.field public final OooOOo:Lorg/jeasy/rules/core/DefaultRulesEngine;

.field public final OooOOo0:Llyiahf/vczjk/wx7;

.field public OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

.field public OooOo:Landroid/os/Handler;

.field public final OooOo0:Llyiahf/vczjk/sc9;

.field public OooOo00:Llyiahf/vczjk/pb7;

.field public final OooOo0O:Llyiahf/vczjk/tg7;

.field public final OooOo0o:Ljava/util/concurrent/ConcurrentHashMap;

.field public OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

.field public OooOoO0:Llyiahf/vczjk/ld9;

.field public OooOoOO:Llyiahf/vczjk/nma;

.field public OooOoo:Z

.field public OooOoo0:Z

.field public final OooOooO:Llyiahf/vczjk/nk3;

.field public final OooOooo:Ljava/util/concurrent/atomic/AtomicReference;

.field public final Oooo:Llyiahf/vczjk/u87;

.field public Oooo0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

.field public final Oooo000:Ljava/util/concurrent/atomic/AtomicReference;

.field public final Oooo00O:Landroid/os/RemoteCallbackList;

.field public final Oooo00o:Landroid/os/RemoteCallbackList;

.field public final Oooo0O0:Llyiahf/vczjk/sc9;

.field public final Oooo0OO:Lnow/fortuitous/profile/ProfileService$monitor$1;

.field public final Oooo0o:Llyiahf/vczjk/b97;

.field public final Oooo0o0:Llyiahf/vczjk/c97;

.field public final Oooo0oO:Llyiahf/vczjk/j97;

.field public final Oooo0oo:Llyiahf/vczjk/v87;

.field public final OoooO:Llyiahf/vczjk/w87;

.field public final OoooO0:Llyiahf/vczjk/x87;

.field public final OoooO00:Llyiahf/vczjk/f97;

.field public final OoooO0O:Llyiahf/vczjk/i97;

.field public final OoooOO0:Llyiahf/vczjk/g97;

.field public final OoooOOO:Llyiahf/vczjk/e97;

.field public final OoooOOo:Llyiahf/vczjk/a97;

.field public final OoooOo0:Llyiahf/vczjk/k97;

.field public final OoooOoO:Llyiahf/vczjk/z87;

.field public OoooOoo:Z

.field public final o000oOoO:Llyiahf/vczjk/h97;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fo9;)V
    .locals 7

    const-string v0, "s"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/aq9;-><init>(Llyiahf/vczjk/fo9;)V

    new-instance p1, Llyiahf/vczjk/up3;

    const/16 v0, 0x14

    invoke-direct {p1, v0}, Llyiahf/vczjk/up3;-><init>(I)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0:Llyiahf/vczjk/up3;

    new-instance p1, Llyiahf/vczjk/wx7;

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    invoke-direct {p1, v0}, Llyiahf/vczjk/wx7;-><init>(Ljava/util/Set;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOo0:Llyiahf/vczjk/wx7;

    new-instance p1, Lorg/jeasy/rules/core/DefaultRulesEngine;

    invoke-direct {p1}, Lorg/jeasy/rules/core/DefaultRulesEngine;-><init>()V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOo:Lorg/jeasy/rules/core/DefaultRulesEngine;

    new-instance p1, Llyiahf/vczjk/p35;

    const/16 v0, 0x12

    invoke-direct {p1, v0}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOo0:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/tg7;

    const/16 v0, 0x1b

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOo0O:Llyiahf/vczjk/tg7;

    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOo0o:Ljava/util/concurrent/ConcurrentHashMap;

    const/4 p1, 0x1

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOoo0:Z

    new-instance p1, Llyiahf/vczjk/nk3;

    invoke-direct {p1}, Llyiahf/vczjk/nk3;-><init>()V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    new-instance v0, Lnow/fortuitous/profile/WifiState;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2, v2}, Lnow/fortuitous/profile/WifiState;-><init>(ZLjava/lang/String;Ljava/lang/String;)V

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOooo:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    new-instance v0, Lgithub/tornaco/android/thanos/core/profile/state/BatteryState;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v2, 0x0

    const/16 v5, 0xf

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v6}, Lgithub/tornaco/android/thanos/core/profile/state/BatteryState;-><init>(IZZZILlyiahf/vczjk/n12;)V

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo000:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance p1, Landroid/os/RemoteCallbackList;

    invoke-direct {p1}, Landroid/os/RemoteCallbackList;-><init>()V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00O:Landroid/os/RemoteCallbackList;

    new-instance p1, Landroid/os/RemoteCallbackList;

    invoke-direct {p1}, Landroid/os/RemoteCallbackList;-><init>()V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00o:Landroid/os/RemoteCallbackList;

    new-instance v0, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    const/4 v2, -0x1

    const/4 v3, -0x1

    const v1, 0x3f5c28f6    # 0.86f

    const/16 v4, 0xe

    const-wide/16 v5, 0xfa0

    invoke-direct/range {v0 .. v6}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;-><init>(FIIIJ)V

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    new-instance p1, Llyiahf/vczjk/q87;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/q87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0O0:Llyiahf/vczjk/sc9;

    new-instance p1, Lnow/fortuitous/profile/ProfileService$monitor$1;

    invoke-direct {p1, p0}, Lnow/fortuitous/profile/ProfileService$monitor$1;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0OO:Lnow/fortuitous/profile/ProfileService$monitor$1;

    new-instance p1, Llyiahf/vczjk/c97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/c97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0o0:Llyiahf/vczjk/c97;

    new-instance p1, Llyiahf/vczjk/b97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/b97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0o:Llyiahf/vczjk/b97;

    new-instance p1, Llyiahf/vczjk/j97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/j97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0oO:Llyiahf/vczjk/j97;

    new-instance p1, Llyiahf/vczjk/v87;

    invoke-direct {p1, p0}, Llyiahf/vczjk/v87;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0oo:Llyiahf/vczjk/v87;

    new-instance p1, Llyiahf/vczjk/u87;

    invoke-direct {p1, p0}, Llyiahf/vczjk/u87;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo:Llyiahf/vczjk/u87;

    new-instance p1, Llyiahf/vczjk/f97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/f97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooO00:Llyiahf/vczjk/f97;

    new-instance p1, Llyiahf/vczjk/x87;

    invoke-direct {p1, p0}, Llyiahf/vczjk/x87;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooO0:Llyiahf/vczjk/x87;

    new-instance p1, Llyiahf/vczjk/i97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/i97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooO0O:Llyiahf/vczjk/i97;

    new-instance p1, Llyiahf/vczjk/w87;

    invoke-direct {p1, p0}, Llyiahf/vczjk/w87;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooO:Llyiahf/vczjk/w87;

    new-instance p1, Llyiahf/vczjk/g97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/g97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOO0:Llyiahf/vczjk/g97;

    new-instance p1, Llyiahf/vczjk/h97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/h97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->o000oOoO:Llyiahf/vczjk/h97;

    new-instance p1, Llyiahf/vczjk/e97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/e97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOOO:Llyiahf/vczjk/e97;

    new-instance p1, Llyiahf/vczjk/a97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/a97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOOo:Llyiahf/vczjk/a97;

    new-instance p1, Llyiahf/vczjk/k97;

    invoke-direct {p1, p0}, Llyiahf/vczjk/k97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOo0:Llyiahf/vczjk/k97;

    new-instance p1, Llyiahf/vczjk/z87;

    invoke-direct {p1, p0}, Llyiahf/vczjk/z87;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOoO:Llyiahf/vczjk/z87;

    return-void
.end method

.method public static OooOo0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I
    .locals 3

    invoke-virtual {p0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result p0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Thanox_Profile_AutoConfig_App_Notification_ID_"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "-"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/x26;->OooO00o(Ljava/lang/String;)I

    move-result p0

    return p0
.end method


# virtual methods
.method public final OooOO0o(Landroid/content/Context;)V
    .locals 6

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-super {p0, p1}, Llyiahf/vczjk/td9;->OooOO0o(Landroid/content/Context;)V

    invoke-static {}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->get()Lgithub/tornaco/android/thanos/core/persist/RepoFactory;

    move-result-object v0

    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOoO0()Ljava/io/File;

    move-result-object v2

    const-string v3, "global_rule_vars.xml"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->getOrCreateStringMapRepo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    move-result-object v0

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    const-string v0, "ProfileService"

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/HandlerUtils;->newHandlerOfNewThread(Ljava/lang/String;)Landroid/os/Handler;

    move-result-object v0

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo:Landroid/os/Handler;

    const/4 v1, 0x0

    const-string v2, "serverHandler"

    if-eqz v0, :cond_1

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "ProfileService server handler: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-static {}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->get()Lgithub/tornaco/android/thanos/core/persist/RepoFactory;

    move-result-object v0

    new-instance v3, Ljava/io/File;

    const/4 v4, 0x0

    invoke-static {v4}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v4

    const-string v5, "profile_alarm_records.xml"

    invoke-direct {v3, v4, v5}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v3}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v3

    const-class v4, Lnow/fortuitous/profile/engine/AlarmEngineRepo;

    invoke-virtual {v0, v3, v4}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->getOrCreateJsonObjectSetRepo(Ljava/lang/String;Ljava/lang/Class;)Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    move-result-object v0

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    new-instance v0, Llyiahf/vczjk/ld9;

    iget-object v3, p0, Lnow/fortuitous/profile/ProfileService;->OooOo:Landroid/os/Handler;

    if-eqz v3, :cond_0

    new-instance v1, Llyiahf/vczjk/r87;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/r87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    invoke-direct {v0, p1, v3, v1}, Llyiahf/vczjk/ld9;-><init>(Landroid/content/Context;Landroid/os/Handler;Llyiahf/vczjk/r87;)V

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    return-void

    :cond_0
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final OooOOOO()V
    .locals 3

    invoke-super {p0}, Llyiahf/vczjk/td9;->OooOOOO()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0OO:Lnow/fortuitous/profile/ProfileService$monitor$1;

    iget-object v1, v0, Lnow/fortuitous/pm/PackageMonitor;->OooO0O0:Landroid/content/Context;

    const/4 v2, 0x0

    if-nez v1, :cond_0

    const-string v0, "Not registered"

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    iput-object v2, v0, Lnow/fortuitous/pm/PackageMonitor;->OooO0O0:Landroid/content/Context;

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo0:Llyiahf/vczjk/i36;

    iget-object v1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOOO:Llyiahf/vczjk/e97;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/i36;->unRegisterObserver(Lgithub/tornaco/android/thanos/core/n/INotificationObserver;)V

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0O0:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/y87;

    invoke-virtual {v0, v1}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    :cond_1
    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_2

    return-void

    :cond_2
    const-string v0, "alarmEngine"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2
.end method

.method public final OooOOOo()V
    .locals 6

    invoke-super {p0}, Llyiahf/vczjk/td9;->OooOOOo()V

    invoke-virtual {p0}, Lnow/fortuitous/profile/ProfileService;->OooOoo()V

    invoke-virtual {p0}, Lnow/fortuitous/profile/ProfileService;->OooOoo0()V

    new-instance v0, Llyiahf/vczjk/d97;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d97;-><init>(Lnow/fortuitous/profile/ProfileService;)V

    iget-object v1, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v1, v1, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/o27;->registerSettingsChangeListener(Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener;)Z

    new-instance v0, Llyiahf/vczjk/bh6;

    invoke-direct {v0, p0}, Llyiahf/vczjk/bh6;-><init>(Ljava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/zi1;->OooO0O0:Llyiahf/vczjk/bh6;

    new-instance v0, Llyiahf/vczjk/s87;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/s87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    new-instance v1, Llyiahf/vczjk/y51;

    const/4 v2, 0x1

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    const/4 v1, 0x0

    const-string v2, "alarmEngine"

    if-eqz v0, :cond_5

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->getAll()Ljava/util/Set;

    move-result-object v0

    const-string v3, "getAll(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v4

    iget-object v5, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    if-eqz v5, :cond_2

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ld9;->Oooo0(Lgithub/tornaco/android/thanos/core/alarm/Alarm;)V

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->isEnabled()Z

    move-result v3

    if-eqz v3, :cond_0

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v5, "Will schedule enabled alarm systemReady: "

    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    iget-object v3, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    if-eqz v3, :cond_1

    const-string v5, "systemReady"

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/ld9;->OooooOo(Lgithub/tornaco/android/thanos/core/alarm/Alarm;Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_3
    return-void

    :cond_4
    const-string v0, "alarmEngineRepo"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_5
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final OooOo(Llyiahf/vczjk/gv2;)V
    .locals 7

    invoke-virtual {p0}, Lnow/fortuitous/profile/ProfileService;->getAllGlobalRuleVarNames()[Ljava/lang/String;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, v0, v2

    invoke-virtual {p0, v3}, Lnow/fortuitous/profile/ProfileService;->getGlobalRuleVarByName(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/sy;->o0000oO([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    invoke-static {v4}, Lcom/google/common/collect/Lists;->OooO00o(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v4

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "globalVarOf$"

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1, v3, v4}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final OooOo0O()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/bp9;->OooO00o:Ljava/util/HashSet;

    const-string v1, "thanox.feature.profile"

    invoke-virtual {v0, v1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0o:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo0o(Llyiahf/vczjk/gv2;)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    sget-object v1, Llyiahf/vczjk/sl3;->OooOOO:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v2, 0x0

    const/4 v3, 0x1

    invoke-virtual {v1, v2, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    move-result v1

    sget-object v3, Llyiahf/vczjk/sl3;->OooOOOO:Ljava/util/HashMap;

    if-eqz v1, :cond_1

    const-string v1, "buildHandleMap..."

    invoke-static {v1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/sl3;->values()[Llyiahf/vczjk/sl3;

    move-result-object v1

    array-length v4, v1

    :goto_0
    if-ge v2, v4, :cond_1

    aget-object v5, v1, v2

    sget-object v6, Llyiahf/vczjk/sl3;->OooOOO0:Llyiahf/vczjk/il3;

    if-eq v5, v6, :cond_0

    invoke-virtual {v5}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    invoke-virtual {v5, v0, v7}, Llyiahf/vczjk/sl3;->OooO00o(Landroid/content/Context;Llyiahf/vczjk/fo9;)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v7

    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "buildHandleMap, add handle: "

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v9, ", "

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-virtual {v3, v6, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {v3}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "fact name must not be null"

    invoke-static {v1, v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/gv2;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/dv2;

    move-result-object v2

    if-eqz v2, :cond_2

    iget-object v2, v2, Llyiahf/vczjk/dv2;->OooO0O0:Ljava/lang/Object;

    goto :goto_2

    :cond_2
    const/4 v2, 0x0

    :goto_2
    if-nez v2, :cond_3

    invoke-virtual {v3, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Dup handle name: "

    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    new-instance v0, Llyiahf/vczjk/oO0OOo0o;

    const/4 v1, 0x1

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/oO0OOo0o;-><init>(IZ)V

    if-eqz p1, :cond_5

    iput-object p1, v0, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    const-string v1, "Actor"

    invoke-virtual {v1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    return-void

    :cond_5
    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "facts is marked non-null but is null"

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOoO(Llyiahf/vczjk/gv2;Ljava/lang/String;)V
    .locals 3

    const-string v0, "facts"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "reason"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo:Landroid/os/Handler;

    const/4 v1, 0x0

    const-string v2, "serverHandler"

    if-eqz v0, :cond_2

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OoooOoo:Z

    if-nez v0, :cond_0

    const-string v0, "publishFacts, installRulesAsyncCompleted is false"

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo:Landroid/os/Handler;

    if-eqz v0, :cond_1

    new-instance v1, Llyiahf/vczjk/oOO0;

    const/16 v2, 0xe

    invoke-direct {v1, p0, p1, v2, p2}, Llyiahf/vczjk/oOO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void

    :cond_1
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final OooOoO0(Llyiahf/vczjk/gv2;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    const-string v1, "thanos"

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    const-string v1, "thanox"

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    const-string v0, "_thanos"

    iget-object v1, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    const-string v0, "_thanox"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    const-string v0, "_profile"

    iget-object v1, v1, Llyiahf/vczjk/fo9;->OooOoO0:Lnow/fortuitous/profile/ProfileService;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo0o:Ljava/util/concurrent/ConcurrentHashMap;

    const-string v1, "ruleKV"

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/gv2;->OooO0OO(Ljava/lang/String;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooOoOO(Llyiahf/vczjk/gv2;Ljava/lang/String;)V
    .locals 2

    const-string v0, "facts"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "reason"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Lnow/fortuitous/profile/ProfileService;->OooOo0O()Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0o:Z

    if-nez v0, :cond_1

    const-string p1, "Profile not enabled, won\'t fire any fact."

    invoke-static {p1}, Llyiahf/vczjk/l87;->OooO0O0(Ljava/lang/String;)V

    return-void

    :cond_1
    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOo0:Llyiahf/vczjk/wx7;

    iget-object v1, v0, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-virtual {v1}, Ljava/util/TreeSet;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_2

    const-string p1, "No rules registered, won\'t fire any."

    invoke-static {p1}, Llyiahf/vczjk/l87;->OooO0O0(Ljava/lang/String;)V

    return-void

    :cond_2
    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->OooOo(Llyiahf/vczjk/gv2;)V

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->OooOo0o(Llyiahf/vczjk/gv2;)V

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->OooOoO0(Llyiahf/vczjk/gv2;)V

    const-string v1, "publishFactsInternal, reason: "

    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/l87;->OooO0O0(Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/wx7;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0000O0(Ljava/lang/Iterable;)Ljava/util/HashSet;

    move-result-object v0

    invoke-direct {p2, v0}, Llyiahf/vczjk/wx7;-><init>(Ljava/util/Set;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOo:Lorg/jeasy/rules/core/DefaultRulesEngine;

    invoke-virtual {v0, p2, p1}, Lorg/jeasy/rules/core/DefaultRulesEngine;->fire(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    return-void
.end method

.method public final OooOoo()V
    .locals 11

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0OO:Lnow/fortuitous/profile/ProfileService$monitor$1;

    iget-object v1, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    sget-object v2, Landroid/os/UserHandle;->CURRENT:Landroid/os/UserHandle;

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v4, v4, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v0, v1, v2, v3, v4}, Lnow/fortuitous/pm/PackageMonitor;->OooO0o0(Landroid/content/Context;Landroid/os/UserHandle;Llyiahf/vczjk/nq2;Llyiahf/vczjk/uv6;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.front_pkg.changed"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0o0:Llyiahf/vczjk/c97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.front_activity.changed"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0o:Llyiahf/vczjk/b97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.task.removed"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0oO:Llyiahf/vczjk/j97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.activity.resumed"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0oo:Llyiahf/vczjk/v87;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.activity.created"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo:Llyiahf/vczjk/u87;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "thanox.a.package.stopped"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooO00:Llyiahf/vczjk/f97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "android.intent.action.BOOT_COMPLETED"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooO0:Llyiahf/vczjk/x87;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "android.intent.action.BATTERY_CHANGED"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooO:Llyiahf/vczjk/w87;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "android.intent.action.ACTION_POWER_CONNECTED"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooOO0:Llyiahf/vczjk/g97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v0

    new-instance v1, Landroid/content/IntentFilter;

    const-string v2, "android.intent.action.ACTION_POWER_DISCONNECTED"

    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->o000oOoO:Llyiahf/vczjk/h97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    new-instance v0, Landroid/content/IntentFilter;

    const-string v1, "android.bluetooth.adapter.action.STATE_CHANGED"

    invoke-direct {v0, v1}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    const-string v1, "android.bluetooth.adapter.action.CONNECTION_STATE_CHANGED"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v1

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooOoO:Llyiahf/vczjk/z87;

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    new-instance v0, Landroid/content/IntentFilter;

    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    const-string v1, "android.intent.action.SCREEN_OFF"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v1, "android.intent.action.SCREEN_ON"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v1, "android.intent.action.USER_PRESENT"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v1

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooO0O:Llyiahf/vczjk/i97;

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo0:Llyiahf/vczjk/i36;

    iget-object v1, p0, Lnow/fortuitous/profile/ProfileService;->OoooOOO:Llyiahf/vczjk/e97;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/i36;->registerObserver(Lgithub/tornaco/android/thanos/core/n/INotificationObserver;)V

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo00:Llyiahf/vczjk/mf7;

    sget-object v1, Lgithub/tornaco/android/thanos/core/push/PushChannel;->FCM_GCM:Lgithub/tornaco/android/thanos/core/push/PushChannel;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mf7;->registerChannel(Lgithub/tornaco/android/thanos/core/push/PushChannel;)V

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo00:Llyiahf/vczjk/mf7;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/push/PushChannel;->getChannelId()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooOOo:Llyiahf/vczjk/a97;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/mf7;->registerChannelHandler(Ljava/lang/String;Lgithub/tornaco/android/thanos/core/push/IChannelHandler;)V

    new-instance v0, Llyiahf/vczjk/q87;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/q87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    :try_start_0
    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isOOrAbove()Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/pma;

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/t87;

    const/4 v4, 0x0

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/t87;-><init>(Llyiahf/vczjk/q87;I)V

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/pma;-><init>(Landroid/content/Context;Llyiahf/vczjk/t87;)V

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/qma;

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/t87;

    const/4 v4, 0x1

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/t87;-><init>(Llyiahf/vczjk/q87;I)V

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/qma;-><init>(Landroid/content/Context;Llyiahf/vczjk/t87;)V

    :goto_0
    iput-object v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOoOO:Llyiahf/vczjk/nma;

    invoke-virtual {v1}, Llyiahf/vczjk/nma;->OooO0O0()V

    new-instance v0, Landroid/content/IntentFilter;

    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    const-string v1, "android.net.wifi.CONFIGURED_NETWORKS_CHANGE"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v1, "android.net.wifi.STATE_CHANGE"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v1, "android.net.wifi.WIFI_STATE_CHANGED"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v1, "android.net.wifi.RSSI_CHANGED"

    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/hr2;->OooO00o()Llyiahf/vczjk/hr2;

    move-result-object v1

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OoooOo0:Llyiahf/vczjk/k97;

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/hr2;->OooO0OO(Landroid/content/IntentFilter;Lgithub/tornaco/android/thanos/core/app/event/IEventSubscriber;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :goto_1
    const-string v1, "Fail init WifiStatusTracker"

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :goto_2
    const/4 v1, 0x0

    :try_start_1
    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    if-eqz v0, :cond_1

    const-string v3, "screen_brightness"

    invoke-static {v3}, Landroid/provider/Settings$System;->getUriFor(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v3

    iget-object v4, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0O0:Llyiahf/vczjk/sc9;

    invoke-virtual {v4}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/y87;

    invoke-virtual {v0, v3, v2, v4}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    goto :goto_3

    :catchall_1
    move-exception v0

    goto :goto_4

    :cond_1
    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v0

    if-eqz v0, :cond_2

    const-string v3, "screen_brightness_mode"

    invoke-static {v3}, Landroid/provider/Settings$System;->getUriFor(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v3

    iget-object v4, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0O0:Llyiahf/vczjk/sc9;

    invoke-virtual {v4}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/y87;

    invoke-virtual {v0, v3, v2, v4}, Landroid/content/ContentResolver;->registerContentObserver(Landroid/net/Uri;ZLandroid/database/ContentObserver;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_5

    :cond_2
    move-object v0, v1

    goto :goto_5

    :goto_4
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_5
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_3

    const-string v2, "registerBrightnessListener error"

    invoke-static {v2, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v2, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v3, Llyiahf/vczjk/wg8;->Ooooo00:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v3

    iget-object v0, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/mi;->OooOoO0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :try_start_2
    iget-object v3, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    const-class v4, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    invoke-virtual {v3, v4, v0}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    goto :goto_6

    :catchall_2
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_6
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v3

    if-nez v3, :cond_4

    move-object v1, v0

    goto :goto_7

    :cond_4
    const-string v0, "Error parse DanmuUISettings"

    invoke-static {v0, v3}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    iget-object v0, v2, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v2, Llyiahf/vczjk/wg8;->Ooooo00:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/o27;->putString(Ljava/lang/String;Ljava/lang/String;)Z

    :goto_7
    check-cast v1, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    if-eqz v1, :cond_9

    new-instance v2, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getAlpha()F

    move-result v3

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getBackgroundColor()I

    move-result v0

    const/4 v4, -0x1

    if-nez v0, :cond_5

    move v0, v4

    goto :goto_8

    :cond_5
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getBackgroundColor()I

    move-result v0

    :goto_8
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextColor()I

    move-result v5

    if-nez v5, :cond_6

    :goto_9
    move v5, v4

    goto :goto_a

    :cond_6
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextColor()I

    move-result v4

    goto :goto_9

    :goto_a
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextSizeSp()I

    move-result v4

    if-nez v4, :cond_7

    const/16 v4, 0xe

    :goto_b
    move v6, v4

    goto :goto_c

    :cond_7
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextSizeSp()I

    move-result v4

    goto :goto_b

    :goto_c
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getDuration()J

    move-result-wide v7

    const-wide/16 v9, 0x0

    cmp-long v4, v7, v9

    if-nez v4, :cond_8

    const-wide/16 v7, 0x4

    :goto_d
    move v4, v0

    goto :goto_e

    :cond_8
    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getDuration()J

    move-result-wide v7

    goto :goto_d

    :goto_e
    invoke-direct/range {v2 .. v8}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;-><init>(FIIIJ)V

    iput-object v2, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "danmuUISettings: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    :cond_9
    return-void
.end method

.method public final OooOoo0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0O:Z

    sget-object v1, Llyiahf/vczjk/wg8;->Ooooo0o:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0o:Z

    sget-object v1, Llyiahf/vczjk/wg8;->OooooO0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    sput-boolean v1, Llyiahf/vczjk/l87;->OooO00o:Z

    sget-object v1, Llyiahf/vczjk/wg8;->OooooOo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOO:Z

    sget-object v1, Llyiahf/vczjk/wg8;->Oooooo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOo:Z

    sget-object v1, Llyiahf/vczjk/wg8;->oo000o:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO:Z

    sget-object v1, Llyiahf/vczjk/wg8;->OooooOO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOoo:Z

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOoO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget-object v0, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/mi;->OooOoO0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    return-void
.end method

.method public final OooOooO(IZ)Z
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    const/4 v1, 0x0

    const-string v2, "ruleRepo"

    if-eqz v0, :cond_4

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoOO(I)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object v0

    const/4 v3, 0x0

    if-eqz v0, :cond_3

    iget-object v4, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v4, :cond_2

    invoke-virtual {v4}, Llyiahf/vczjk/pb7;->OooOOOO()Lgithub/tornaco/android/thanos/db/profile/RuleDb;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/db/profile/RuleDb;->ruleDao()Lgithub/tornaco/android/thanos/db/profile/RuleDao;

    move-result-object v1

    invoke-interface {v1, p1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao;->loadById(I)Lgithub/tornaco/android/thanos/db/profile/RuleRecord;

    move-result-object v1

    if-nez v1, :cond_0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "RuleRepo, setEnabled, rule not found: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1, p2}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->setEnabled(Z)V

    invoke-virtual {v4}, Llyiahf/vczjk/pb7;->OooOOOO()Lgithub/tornaco/android/thanos/db/profile/RuleDb;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/db/profile/RuleDb;->ruleDao()Lgithub/tornaco/android/thanos/db/profile/RuleDao;

    move-result-object v2

    invoke-interface {v2, v1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao;->insert(Lgithub/tornaco/android/thanos/db/profile/RuleRecord;)J

    invoke-virtual {v4}, Llyiahf/vczjk/pb7;->OooOo()V

    :goto_0
    iget-object v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOo0:Llyiahf/vczjk/wx7;

    invoke-virtual {v0}, Lnow/fortuitous/profile/RuleInfoExt;->getRule()Llyiahf/vczjk/nw7;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz p2, :cond_1

    aget-object v0, v0, v3

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, v1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-static {v0}, Lorg/jeasy/rules/core/RuleProxy;->asRule(Ljava/lang/Object;)Llyiahf/vczjk/nw7;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    aget-object v0, v0, v3

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, v1, Llyiahf/vczjk/wx7;->OooOOO0:Ljava/util/TreeSet;

    invoke-static {v0}, Lorg/jeasy/rules/core/RuleProxy;->asRule(Ljava/lang/Object;)Llyiahf/vczjk/nw7;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/TreeSet;->remove(Ljava/lang/Object;)Z

    :goto_1
    new-instance v0, Llyiahf/vczjk/m87;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/m87;-><init>(IZ)V

    new-instance p1, Llyiahf/vczjk/tm4;

    const/16 p2, 0xe

    invoke-direct {p1, p2, p0, v0}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    const/4 p1, 0x1

    return p1

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_3
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "setEnabled, RuleInfo with id "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, " not found.."

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return v3

    :cond_4
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final OooOooo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 8

    iget-boolean v0, p0, Llyiahf/vczjk/td9;->OooO0oO:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;

    move-result-object v0

    invoke-static {p1}, Lnow/fortuitous/profile/ProfileService;->OooOo0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;->cancel(I)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0:Llyiahf/vczjk/up3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/up3;->OooOO0(Landroid/content/Context;)V

    new-instance v0, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    iget-object v1, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    const-string v2, "dev.tornaco.notification.channel.id.Thanos-DEFAULT"

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    new-instance v1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    const-string v3, "github.tornaco.android.thanos"

    invoke-direct {v1, v2, v3}, Lgithub/tornaco/android/thanos/core/app/AppResources;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v4, 0x0

    new-array v5, v4, [Ljava/lang/Object;

    const-string v6, "service_notification_override_thanos"

    invoke-virtual {v1, v6, v5}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v0, v5}, Llyiahf/vczjk/wd9;->OooO00o(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-static {v2, v5}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->loadNameByPkgName(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/CharSequence;

    move-result-object v2

    if-nez v2, :cond_2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v2

    :cond_2
    new-instance v5, Landroid/content/Intent;

    invoke-direct {v5}, Landroid/content/Intent;-><init>()V

    invoke-virtual {v5, v3}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    const-string v6, "now.fortuitous.thanos.apps.AppDetailsActivity"

    invoke-virtual {v5, v3, v6}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    iget-object v3, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v3, v3, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v7

    invoke-virtual {v3, v7, v6}, Llyiahf/vczjk/uv6;->OooOooo(ILjava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v3

    const-string v6, "app"

    invoke-virtual {v5, v6, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    const/high16 v3, 0x10000000

    invoke-virtual {v5, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    const-string v3, "service_notification_apply_auto_template_title"

    new-array v4, v4, [Ljava/lang/Object;

    invoke-virtual {v1, v3, v4}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setContentTitle(Ljava/lang/CharSequence;)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    const-string v3, "service_notification_apply_auto_template_message"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v3, v2}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setContentText(Ljava/lang/CharSequence;)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    const v2, 0x108008a

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setSmallIcon(I)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setAutoCancel(Z)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setVisibility(I)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v3

    invoke-virtual {v3}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v3

    const-string v4, "toString(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/x26;->OooO00o(Ljava/lang/String;)I

    move-result v3

    const/high16 v4, 0x4000000

    invoke-static {v2, v3, v5, v4}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object v2

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->setContentIntent(Landroid/app/PendingIntent;)Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/compat/NotificationCompat$Builder;->build()Landroid/app/Notification;

    move-result-object v0

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isMOrAbove()Z

    move-result v2

    if-eqz v2, :cond_3

    const-string v2, "ic_check_double_fill"

    invoke-virtual {v1, v2}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getIcon(Ljava/lang/String;)Landroid/graphics/drawable/Icon;

    move-result-object v1

    invoke-virtual {v0, v1}, Landroid/app/Notification;->setSmallIcon(Landroid/graphics/drawable/Icon;)V

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;

    move-result-object v1

    invoke-static {p1}, Lnow/fortuitous/profile/ProfileService;->OooOo0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result p1

    invoke-virtual {v1, p1, v0}, Lgithub/tornaco/android/thanos/core/compat/NotificationManagerCompat;->notify(ILandroid/app/Notification;)V

    return-void
.end method

.method public final Oooo000()Ljava/lang/Object;
    .locals 6

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getPowerManager(Landroid/content/Context;)Landroid/os/PowerManager;

    move-result-object v0

    invoke-virtual {v0}, Landroid/os/PowerManager;->getDefaultScreenBrightnessSetting()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    :try_start_1
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    goto :goto_1

    :cond_0
    const-string v0, "Error get defaultScreenBrightnessSetting"

    invoke-static {v0, v1}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    :goto_1
    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    :try_start_2
    iget-object v1, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getPowerManager(Landroid/content/Context;)Landroid/os/PowerManager;

    move-result-object v1

    invoke-virtual {v1}, Landroid/os/PowerManager;->getMinimumScreenBrightnessSetting()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    goto :goto_2

    :catchall_1
    move-exception v1

    :try_start_3
    invoke-static {v1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v1

    :goto_2
    invoke-static {v1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v3

    if-nez v3, :cond_1

    goto :goto_3

    :cond_1
    const-string v1, "Error get minimumScreenBrightnessSetting"

    invoke-static {v1, v3}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    :goto_3
    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    :try_start_4
    iget-object v3, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v3}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getPowerManager(Landroid/content/Context;)Landroid/os/PowerManager;

    move-result-object v3

    invoke-virtual {v3}, Landroid/os/PowerManager;->getMaximumScreenBrightnessSetting()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    goto :goto_4

    :catchall_2
    move-exception v3

    :try_start_5
    invoke-static {v3}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v3

    :goto_4
    invoke-static {v3}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v4

    if-nez v4, :cond_2

    goto :goto_5

    :cond_2
    const-string v3, "Error get maximumScreenBrightnessSetting"

    invoke-static {v3, v4}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    :goto_5
    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    if-eqz v3, :cond_3

    invoke-virtual {v3}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    move-result-object v3

    goto :goto_6

    :catchall_3
    move-exception v0

    goto :goto_7

    :cond_3
    const/4 v3, 0x0

    :goto_6
    const-string v4, "screen_brightness"

    const/4 v5, -0x2

    invoke-static {v3, v4, v0, v5}, Landroid/provider/Settings$System;->getIntForUser(Landroid/content/ContentResolver;Ljava/lang/String;II)I

    move-result v0

    new-instance v3, Lnow/fortuitous/profile/fact/ThanoxFacts;

    invoke-direct {v3}, Lnow/fortuitous/profile/fact/ThanoxFacts;-><init>()V

    const/4 v4, 0x1

    invoke-virtual {v3, v4}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setBrightnessChanged(Z)V

    invoke-virtual {v3, v0}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setBrightness(I)V

    invoke-virtual {v3, v1}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setMinBrightness(I)V

    invoke-virtual {v3, v2}, Lnow/fortuitous/profile/fact/ThanoxFacts;->setMaxBrightness(I)V

    invoke-virtual {v3}, Lnow/fortuitous/profile/fact/ThanoxFacts;->compose()Llyiahf/vczjk/gv2;

    move-result-object v0

    const-string v1, "brightnessChanged"

    invoke-virtual {p0, v0, v1}, Lnow/fortuitous/profile/ProfileService;->OooOoO(Llyiahf/vczjk/gv2;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    goto :goto_8

    :goto_7
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_8
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-eqz v1, :cond_4

    const-string v2, "updateBrightnessState error"

    invoke-static {v2, v1}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_4
    return-object v0
.end method

.method public final addAlarmEngine(Lgithub/tornaco/android/thanos/core/alarm/Alarm;)V
    .locals 5

    const-string v0, "alarm"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz v0, :cond_0

    new-instance v1, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    const/4 v2, 0x0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-direct {v1, p1, v2, v3, v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;-><init>(Lgithub/tornaco/android/thanos/core/alarm/Alarm;ZJ)V

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->add(Ljava/lang/Object;)Z

    return-void

    :cond_0
    const-string p1, "alarmEngineRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final addConfigTemplate(Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;)Z
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOOOO()Ljava/io/File;

    move-result-object v2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    const-string v1, "addConfigTemplate, Template file exists..."

    invoke-static {v1, p1}, Llyiahf/vczjk/ix8;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    return v0

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/sb;->OooOo0O(Ljava/io/File;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->writeString(Ljava/lang/String;Ljava/lang/String;)Z

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    const/4 p1, 0x1

    return p1
.end method

.method public final addConsoleLogSink(Lgithub/tornaco/android/thanos/core/profile/ILogSink;)V
    .locals 1

    const-string v0, "sink"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00o:Landroid/os/RemoteCallbackList;

    invoke-virtual {v0, p1}, Landroid/os/RemoteCallbackList;->register(Landroid/os/IInterface;)Z

    return-void
.end method

.method public final addGlobalRuleVar(Ljava/lang/String;[Ljava/lang/String;)Z
    .locals 1

    const-string v0, "varName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "varArray"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-static {v0, p2}, Llyiahf/vczjk/j21;->OoooOoo(Ljava/util/Collection;[Ljava/lang/Object;)V

    iget-object p2, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x1

    return p1

    :cond_0
    const-string p1, "globalRuleVarRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final addRule(Ljava/lang/String;ILjava/lang/String;Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p4

    const/16 v2, 0x10

    const/4 v4, 0x1

    const-string v5, "|"

    const-string v6, "author"

    move-object/from16 v11, p1

    invoke-static {v11, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    invoke-virtual {v0}, Llyiahf/vczjk/td9;->OooOOO0()Landroid/content/Context;

    move-result-object v6

    :try_start_0
    invoke-static {v6}, Llyiahf/vczjk/fu6;->OooOoO(Landroid/content/Context;)[Landroid/content/pm/Signature;

    move-result-object v6

    array-length v7, v6

    move v9, v4

    const/4 v8, 0x0

    const/4 v10, 0x0

    :goto_0
    if-ge v8, v7, :cond_2

    aget-object v12, v6, v8

    add-int/lit8 v13, v10, 0x1

    const-string v14, "SHA1"

    invoke-static {v14}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v14

    invoke-virtual {v12}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object v12

    invoke-virtual {v14, v12}, Ljava/security/MessageDigest;->update([B)V

    invoke-virtual {v14}, Ljava/security/MessageDigest;->digest()[B

    move-result-object v12

    new-array v14, v2, [C

    fill-array-data v14, :array_0

    array-length v15, v12

    mul-int/lit8 v15, v15, 0x2

    new-array v15, v15, [C

    array-length v3, v12

    const/4 v2, 0x0

    :goto_1
    if-ge v2, v3, :cond_0

    move/from16 v16, v4

    aget-byte v4, v12, v2

    move/from16 v17, v2

    and-int/lit16 v2, v4, 0xff

    mul-int/lit8 v18, v17, 0x2

    ushr-int/lit8 v2, v2, 0x4

    aget-char v2, v14, v2

    aput-char v2, v15, v18

    add-int/lit8 v18, v18, 0x1

    and-int/lit8 v2, v4, 0xf

    aget-char v2, v14, v2

    aput-char v2, v15, v18

    add-int/lit8 v2, v17, 0x1

    move/from16 v4, v16

    goto :goto_1

    :cond_0
    move/from16 v16, v4

    new-instance v2, Ljava/lang/String;

    invoke-direct {v2, v15}, Ljava/lang/String;-><init>([C)V

    const/4 v3, 0x3

    new-array v3, v3, [B

    fill-array-data v3, :array_1

    new-instance v4, Ljava/lang/String;

    sget-object v12, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-direct {v4, v3, v12}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    invoke-static {v4}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v3

    new-instance v4, Ljava/math/BigInteger;

    invoke-virtual {v2, v12}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v2

    const-string v12, "getBytes(...)"

    invoke-static {v2, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object v2

    move/from16 v3, v16

    invoke-direct {v4, v3, v2}, Ljava/math/BigInteger;-><init>(I[B)V

    const/16 v2, 0x10

    invoke-virtual {v4, v2}, Ljava/math/BigInteger;->toString(I)Ljava/lang/String;

    move-result-object v3

    const-string v4, "toString(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v4, 0x20

    invoke-static {v4, v3}, Llyiahf/vczjk/z69;->OoooOo0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const-string v4, "25cc0926b09a6e73798de05977c420f7"

    filled-new-array {v5}, [Ljava/lang/String;

    move-result-object v12

    invoke-static {v4, v12}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v4

    invoke-interface {v4, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    const-string v4, "fbb0fffe49334e78f6f901c2a144314f"

    filled-new-array {v5}, [Ljava/lang/String;

    move-result-object v12

    invoke-static {v4, v12}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v4

    invoke-interface {v4, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    const-string v4, "16d5c7e8d44ba3546f725b156a925cdb"

    filled-new-array {v5}, [Ljava/lang/String;

    move-result-object v12

    invoke-static {v4, v12}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v4

    invoke-interface {v4, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v3, :cond_1

    const/4 v9, 0x0

    :cond_1
    const/16 v16, 0x1

    add-int/lit8 v8, v8, 0x1

    move v10, v13

    move/from16 v4, v16

    goto/16 :goto_0

    :catchall_0
    const/4 v9, 0x0

    :cond_2
    if-eqz v9, :cond_4

    const-string v2, "RuleInfo content is null"

    move-object/from16 v8, p3

    invoke-static {v8, v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    iget-object v7, v0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v7, :cond_3

    new-instance v13, Llyiahf/vczjk/n87;

    const/4 v2, 0x0

    invoke-direct {v13, v1, v0, v2}, Llyiahf/vczjk/n87;-><init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;Lnow/fortuitous/profile/ProfileService;I)V

    new-instance v14, Llyiahf/vczjk/o87;

    invoke-direct {v14, v1, v2}, Llyiahf/vczjk/o87;-><init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V

    new-instance v12, Llyiahf/vczjk/r07;

    const/16 v1, 0x11

    invoke-direct {v12, v1}, Llyiahf/vczjk/r07;-><init>(I)V

    new-instance v15, Llyiahf/vczjk/r07;

    const/16 v1, 0x12

    invoke-direct {v15, v1}, Llyiahf/vczjk/r07;-><init>(I)V

    move/from16 v10, p2

    move/from16 v9, p5

    invoke-virtual/range {v7 .. v15}, Llyiahf/vczjk/pb7;->OooO0o(Ljava/lang/String;IILjava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    goto :goto_2

    :cond_3
    const-string v1, "ruleRepo"

    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v1, 0x0

    throw v1

    :cond_4
    :goto_2
    return-void

    nop

    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x41s
        0x42s
        0x43s
        0x44s
        0x45s
        0x46s
    .end array-data

    :array_1
    .array-data 1
        0x4dt
        0x44t
        0x35t
    .end array-data
.end method

.method public final addRuleIfNotExists(Ljava/lang/String;ILjava/lang/String;Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v1, p4

    const/16 v2, 0x10

    const/4 v3, 0x1

    const-string v4, "|"

    const-string v5, "author"

    move-object/from16 v10, p1

    invoke-static {v10, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const-string v5, "RuleInfo content is null"

    move-object/from16 v7, p3

    invoke-static {v7, v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/td9;->OooOOO0()Landroid/content/Context;

    move-result-object v5

    :try_start_0
    invoke-static {v5}, Llyiahf/vczjk/fu6;->OooOoO(Landroid/content/Context;)[Landroid/content/pm/Signature;

    move-result-object v5

    array-length v8, v5

    move v11, v3

    const/4 v9, 0x0

    const/4 v12, 0x0

    :goto_0
    if-ge v9, v8, :cond_2

    aget-object v13, v5, v9

    add-int/lit8 v14, v12, 0x1

    const-string v15, "SHA1"

    invoke-static {v15}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v15

    invoke-virtual {v13}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object v13

    invoke-virtual {v15, v13}, Ljava/security/MessageDigest;->update([B)V

    invoke-virtual {v15}, Ljava/security/MessageDigest;->digest()[B

    move-result-object v13

    new-array v15, v2, [C

    fill-array-data v15, :array_0

    array-length v6, v13

    mul-int/lit8 v6, v6, 0x2

    new-array v6, v6, [C

    array-length v2, v13

    move/from16 v16, v3

    const/4 v3, 0x0

    :goto_1
    if-ge v3, v2, :cond_0

    move/from16 v17, v2

    aget-byte v2, v13, v3

    move/from16 v18, v3

    and-int/lit16 v3, v2, 0xff

    mul-int/lit8 v19, v18, 0x2

    ushr-int/lit8 v3, v3, 0x4

    aget-char v3, v15, v3

    aput-char v3, v6, v19

    add-int/lit8 v19, v19, 0x1

    and-int/lit8 v2, v2, 0xf

    aget-char v2, v15, v2

    aput-char v2, v6, v19

    add-int/lit8 v3, v18, 0x1

    move/from16 v2, v17

    goto :goto_1

    :cond_0
    new-instance v2, Ljava/lang/String;

    invoke-direct {v2, v6}, Ljava/lang/String;-><init>([C)V

    const/4 v3, 0x3

    new-array v3, v3, [B

    fill-array-data v3, :array_1

    new-instance v6, Ljava/lang/String;

    sget-object v13, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-direct {v6, v3, v13}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    invoke-static {v6}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v3

    new-instance v6, Ljava/math/BigInteger;

    invoke-virtual {v2, v13}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v2

    const-string v13, "getBytes(...)"

    invoke-static {v2, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object v2

    move/from16 v3, v16

    invoke-direct {v6, v3, v2}, Ljava/math/BigInteger;-><init>(I[B)V

    const/16 v2, 0x10

    invoke-virtual {v6, v2}, Ljava/math/BigInteger;->toString(I)Ljava/lang/String;

    move-result-object v3

    const-string v6, "toString(...)"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v6, 0x20

    invoke-static {v6, v3}, Llyiahf/vczjk/z69;->OoooOo0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const-string v6, "25cc0926b09a6e73798de05977c420f7"

    filled-new-array {v4}, [Ljava/lang/String;

    move-result-object v13

    invoke-static {v6, v13}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v6

    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1

    const-string v6, "fbb0fffe49334e78f6f901c2a144314f"

    filled-new-array {v4}, [Ljava/lang/String;

    move-result-object v13

    invoke-static {v6, v13}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v6

    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1

    const-string v6, "16d5c7e8d44ba3546f725b156a925cdb"

    filled-new-array {v4}, [Ljava/lang/String;

    move-result-object v13

    invoke-static {v6, v13}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v6

    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v3, :cond_1

    const/4 v11, 0x0

    :cond_1
    const/16 v16, 0x1

    add-int/lit8 v9, v9, 0x1

    move v12, v14

    const/4 v3, 0x1

    goto/16 :goto_0

    :cond_2
    move v6, v11

    goto :goto_2

    :catchall_0
    const/4 v6, 0x0

    :goto_2
    if-eqz v6, :cond_4

    iget-object v6, v0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v6, :cond_3

    new-instance v11, Llyiahf/vczjk/r87;

    const/4 v3, 0x1

    invoke-direct {v11, v0, v3}, Llyiahf/vczjk/r87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    new-instance v12, Llyiahf/vczjk/n87;

    invoke-direct {v12, v1, v0, v3}, Llyiahf/vczjk/n87;-><init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;Lnow/fortuitous/profile/ProfileService;I)V

    new-instance v13, Llyiahf/vczjk/o87;

    invoke-direct {v13, v1, v3}, Llyiahf/vczjk/o87;-><init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V

    new-instance v14, Llyiahf/vczjk/r07;

    const/4 v1, 0x7

    invoke-direct {v14, v1}, Llyiahf/vczjk/r07;-><init>(I)V

    move/from16 v9, p2

    move/from16 v8, p5

    invoke-virtual/range {v6 .. v14}, Llyiahf/vczjk/pb7;->OooO0o(Ljava/lang/String;IILjava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    goto :goto_3

    :cond_3
    const-string v1, "ruleRepo"

    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v1, 0x0

    throw v1

    :cond_4
    :goto_3
    return-void

    nop

    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x41s
        0x42s
        0x43s
        0x44s
        0x45s
        0x46s
    .end array-data

    :array_1
    .array-data 1
        0x4dt
        0x44t
        0x35t
    .end array-data
.end method

.method public final appendGlobalRuleVar(Ljava/lang/String;[Ljava/lang/String;)Z
    .locals 2

    const-string v0, "varName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "varArray"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->getGlobalRuleVarByName(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/j21;->OoooOoo(Ljava/util/Collection;[Ljava/lang/Object;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/j21;->OoooOoo(Ljava/util/Collection;[Ljava/lang/Object;)V

    iget-object p2, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x1

    return p1

    :cond_0
    const-string p1, "globalRuleVarRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final applyConfigTemplateForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;)Z
    .locals 11

    const-string v0, "pkg"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "template"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "applyConfigTemplateForPackage with template: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getDummyPackageName()Ljava/lang/String;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v1, v0, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v3

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/uv6;->OooOooo(ILjava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "applyConfigTemplateForPackage app "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " not installed!"

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return v2

    :cond_0
    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->systemUserPkg(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v3

    iget-object v4, v0, Llyiahf/vczjk/fo9;->OooO:Llyiahf/vczjk/a;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgBgRestricted(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->setPkgBgRestrictEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgStartBlocking(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->setPkgStartBlockEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->setPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->setPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v6, v0, Llyiahf/vczjk/fo9;->OooOOo:Llyiahf/vczjk/a57;

    invoke-virtual {v6, p2}, Llyiahf/vczjk/a57;->getSelectedFieldsProfileIdForPackage(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v6, v5, v7}, Llyiahf/vczjk/a57;->selectFieldsProfileForPackage(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v7, v0, Llyiahf/vczjk/fo9;->OooOOoo:Llyiahf/vczjk/fw;

    invoke-virtual {v7, p2}, Llyiahf/vczjk/fw;->isPkgOpRemindEnable(Ljava/lang/String;)Z

    move-result v8

    invoke-virtual {v7, v5, v8}, Llyiahf/vczjk/fw;->setPkgOpRemindEnable(Ljava/lang/String;Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v8, v0, Llyiahf/vczjk/fo9;->OooOo0:Llyiahf/vczjk/i36;

    invoke-virtual {v8, p2}, Llyiahf/vczjk/i36;->isScreenOnNotificationEnabledForPkg(Ljava/lang/String;)Z

    move-result v9

    invoke-virtual {v8, v5, v9}, Llyiahf/vczjk/i36;->setScreenOnNotificationEnabledForPkg(Ljava/lang/String;Z)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgSmartStandByEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->Oooooo(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v8, v0, Llyiahf/vczjk/fo9;->OooOOo0:Lnow/fortuitous/app/OooO00o;

    iget-object v9, v8, Lnow/fortuitous/app/OooO00o;->OooOOO:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    invoke-interface {v9, p2}, Lgithub/tornaco/android/thanos/core/persist/i/SetRepo;->has(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v8, v5, v9}, Lnow/fortuitous/app/OooO00o;->setPackageLocked(Ljava/lang/String;Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    iget-object v9, v0, Llyiahf/vczjk/uv6;->OooOo0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    invoke-virtual {v9, p2}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->has(Ljava/lang/String;)Z

    move-result v9

    invoke-virtual {v0, v5, v9}, Llyiahf/vczjk/uv6;->setPackageBlockClearDataEnabled(Ljava/lang/String;Z)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    iget-object v9, v0, Llyiahf/vczjk/uv6;->OooOo0:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    invoke-virtual {v9, p2}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->has(Ljava/lang/String;)Z

    move-result v9

    invoke-virtual {v0, v5, v9}, Llyiahf/vczjk/uv6;->setPackageBlockUninstallEnabled(Ljava/lang/String;Z)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/uv6;->isPkgSmartFreezeEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    const/4 v9, 0x1

    if-eqz v5, :cond_1

    invoke-virtual {v0, p1, v9}, Llyiahf/vczjk/uv6;->setPkgSmartFreezeEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    :cond_1
    invoke-virtual {v8, v3}, Lnow/fortuitous/app/OooO00o;->OooOo0o(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result v5

    invoke-virtual {v8, p1, v5}, Lnow/fortuitous/app/OooO00o;->setLaunchOtherAppSetting(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V

    invoke-virtual {v6, v3}, Llyiahf/vczjk/a57;->getSensorOffSettingsForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result v5

    invoke-virtual {v6, p1, v5}, Llyiahf/vczjk/a57;->setSensorOffSettingsForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/a;->isPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v5

    invoke-virtual {v4, p1, v5}, Llyiahf/vczjk/a;->setPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/uv6;->isPkgShortcutsBlockerEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v3

    invoke-virtual {v0, p1, v3}, Llyiahf/vczjk/uv6;->setPkgShortcutsBlockerEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v3

    invoke-static {v0, v3}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->getAllDeclaredPermissions(Landroid/content/Context;Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    const-string v3, "getAllDeclaredPermissions(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    invoke-static {}, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->getAllOp()Ljava/util/List;

    move-result-object v3

    const-string v4, "getAllOp(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v5

    invoke-static {v5}, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->opToPermission(I)Ljava/lang/String;

    move-result-object v5

    if-eqz v5, :cond_3

    invoke-interface {v0, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->toString()Ljava/lang/String;

    goto :goto_0

    :cond_3
    :goto_1
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v5

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v6, -0x1

    invoke-virtual {v7, v5, v6, p2}, Llyiahf/vczjk/fw;->checkOperationNonCheck(IILjava/lang/String;)I

    move-result v5

    :try_start_0
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    move-result v4

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUid()I

    move-result v6

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v8

    const-string v10, "getPkgName(...)"

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7, v4, v6, v8, v5}, Llyiahf/vczjk/fw;->setMode(IILjava/lang/String;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v4

    new-instance v6, Ljava/lang/StringBuilder;

    const-string v8, "applyConfigTemplateForPackage, Fail set mode "

    invoke-direct {v6, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v5, " for app "

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    new-array v6, v2, [Ljava/lang/Object;

    invoke-static {v5, v6, v4}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    goto :goto_0

    :cond_4
    return v9
.end method

.method public final asBinder()Landroid/os/IBinder;
    .locals 1

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/Noop;->notSupported()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IBinder;

    return-object v0
.end method

.method public final checkRule(Ljava/lang/String;Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;I)V
    .locals 4

    const-string v0, "ruleString"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/pb7;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a27;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    const-string v2, "it"

    if-eqz p3, :cond_2

    const/4 v3, 0x1

    if-eq p3, v3, :cond_0

    if-eqz p2, :cond_4

    const-string p1, "Invalid format."

    invoke-interface {p2, v1, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;->onInvalid(ILjava/lang/String;)V

    return-void

    :cond_0
    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r95;

    new-instance v3, Ljava/io/StringReader;

    invoke-direct {v3, p1}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/r95;->OooO00o(Ljava/io/StringReader;)Lorg/jeasy/rules/core/BasicRule;

    move-result-object v0

    invoke-static {v0, p1, p3}, Llyiahf/vczjk/tp6;->Oooo0oO(Llyiahf/vczjk/nw7;Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    if-eqz p2, :cond_4

    invoke-interface {p2, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;->onValid(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p3

    if-nez p3, :cond_1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p3

    :cond_1
    invoke-static {p3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p2, :cond_4

    invoke-interface {p2, v1, p3}, Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;->onInvalid(ILjava/lang/String;)V

    goto :goto_0

    :cond_2
    :try_start_1
    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r95;

    new-instance v3, Ljava/io/StringReader;

    invoke-direct {v3, p1}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/r95;->OooO00o(Ljava/io/StringReader;)Lorg/jeasy/rules/core/BasicRule;

    move-result-object v0

    invoke-static {v0, p1, p3}, Llyiahf/vczjk/tp6;->Oooo0oO(Llyiahf/vczjk/nw7;Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    if-eqz p2, :cond_4

    invoke-interface {p2, p1}, Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;->onValid(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p3

    if-nez p3, :cond_3

    invoke-virtual {p1}, Ljava/lang/Throwable;->toString()Ljava/lang/String;

    move-result-object p3

    :cond_3
    invoke-static {p3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p2, :cond_4

    invoke-interface {p2, v1, p3}, Lgithub/tornaco/android/thanos/core/profile/IRuleCheckCallback;->onInvalid(ILjava/lang/String;)V

    :cond_4
    :goto_0
    return-void

    :cond_5
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final clearLogs()V
    .locals 4

    invoke-static {}, Llyiahf/vczjk/l87;->OooO00o()Ljava/io/File;

    move-result-object v0

    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "--------------beginning of Profile."

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/d03;->o00Oo0(Ljava/io/File;Ljava/lang/String;)V

    return-void
.end method

.method public final deleteConfigTemplate(Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;)Z
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOOOO()Ljava/io/File;

    move-result-object v2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result v2

    if-nez v2, :cond_1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    const-string v1, "deleteConfigTemplate, Template file not exists..."

    invoke-static {v1, p1}, Llyiahf/vczjk/ix8;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    return v0

    :cond_1
    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->delete(Ljava/io/File;)Z

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getId()Ljava/lang/String;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->setAutoConfigTemplateSelection(Ljava/lang/String;)V

    const-string p1, "deleteConfigTemplate, setAutoConfigTemplateSelection to null"

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    :cond_2
    const/4 p1, 0x1

    return p1
.end method

.method public final deleteRule(I)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->disableRule(I)Z

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOOOO()Lgithub/tornaco/android/thanos/db/profile/RuleDb;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/db/profile/RuleDb;->ruleDao()Lgithub/tornaco/android/thanos/db/profile/RuleDao;

    move-result-object v1

    invoke-interface {v1, p1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao;->deleteById(I)I

    move-result v1

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOo()V

    if-lez v1, :cond_0

    new-instance v0, Llyiahf/vczjk/k21;

    const/4 v1, 0x7

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/k21;-><init>(II)V

    new-instance p1, Llyiahf/vczjk/tm4;

    const/16 v1, 0xe

    invoke-direct {p1, v1, p0, v0}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    :cond_0
    return-void

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final disableRule(I)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Lnow/fortuitous/profile/ProfileService;->OooOooO(IZ)Z

    move-result p1

    return p1
.end method

.method public final disableRuleByName(Ljava/lang/String;)Z
    .locals 2

    const-string v0, "ruleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoo0(Ljava/lang/String;)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object v0

    if-nez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "disableRuleByName, rule with name "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " not found."

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {v0}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getId()I

    move-result p1

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->disableRule(I)Z

    move-result p1

    return p1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V
    .locals 0

    return-void
.end method

.method public final enableRule(I)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const/4 v0, 0x1

    invoke-virtual {p0, p1, v0}, Lnow/fortuitous/profile/ProfileService;->OooOooO(IZ)Z

    move-result p1

    return p1
.end method

.method public final enableRuleByName(Ljava/lang/String;)Z
    .locals 2

    const-string v0, "ruleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoo0(Ljava/lang/String;)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object v0

    if-nez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "enableRuleByName, rule with name "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " not found."

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {v0}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getId()I

    move-result p1

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->enableRule(I)Z

    move-result p1

    return p1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final executeAction(Ljava/lang/String;)V
    .locals 1

    const-string v0, "action"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    new-instance v0, Llyiahf/vczjk/p87;

    invoke-direct {v0, p1, p0}, Llyiahf/vczjk/p87;-><init>(Ljava/lang/String;Lnow/fortuitous/profile/ProfileService;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method

.method public final getAllAlarms()Ljava/util/List;
    .locals 2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->getAll()Ljava/util/Set;

    move-result-object v0

    const-string v1, "getAll(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :cond_0
    const-string v0, "alarmEngineRepo"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final getAllConfigTemplates()Ljava/util/List;
    .locals 6

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOOOO()Ljava/io/File;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/b03;->OooOOO0:Llyiahf/vczjk/b03;

    new-instance v3, Llyiahf/vczjk/oz2;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v2, v4}, Llyiahf/vczjk/oz2;-><init>(Ljava/io/File;Llyiahf/vczjk/b03;Llyiahf/vczjk/uu;)V

    new-instance v1, Llyiahf/vczjk/mz2;

    invoke-direct {v1, v3}, Llyiahf/vczjk/mz2;-><init>(Llyiahf/vczjk/oz2;)V

    :cond_0
    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/o0O0ooO;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/o0O0ooO;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/io/File;

    invoke-virtual {v2}, Ljava/io/File;->isDirectory()Z

    move-result v3

    if-nez v3, :cond_0

    :try_start_0
    iget-object v3, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->readString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const-class v5, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    invoke-virtual {v3, v5, v4}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    if-eqz v3, :cond_0

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->validate()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v3

    invoke-virtual {v2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    invoke-static {v3}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Error parse config template file: "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ", error message: "

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    goto :goto_0

    :cond_1
    return-object v0
.end method

.method public final getAllGlobalRuleVar()[Lgithub/tornaco/android/thanos/core/profile/GlobalVar;
    .locals 8

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p0}, Lnow/fortuitous/profile/ProfileService;->getAllGlobalRuleVarNames()[Ljava/lang/String;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_0

    aget-object v5, v1, v4

    new-instance v6, Lgithub/tornaco/android/thanos/core/profile/GlobalVar;

    invoke-virtual {p0, v5}, Lnow/fortuitous/profile/ProfileService;->getGlobalRuleVarByName(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/sy;->o0000O0([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v7

    invoke-direct {v6, v5, v7}, Lgithub/tornaco/android/thanos/core/profile/GlobalVar;-><init>(Ljava/lang/String;Ljava/util/List;)V

    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    new-array v1, v3, [Lgithub/tornaco/android/thanos/core/profile/GlobalVar;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lgithub/tornaco/android/thanos/core/profile/GlobalVar;

    return-object v0
.end method

.method public final getAllGlobalRuleVarNames()[Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->keySet()Ljava/util/Set;

    move-result-object v0

    const-string v1, "<get-keys>(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/String;

    invoke-interface {v0, v1}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/String;

    return-object v0

    :cond_0
    const-string v0, "globalRuleVarRepo"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final getAllRules()[Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 3

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/pb7;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lnow/fortuitous/profile/RuleInfoExt;

    invoke-virtual {v2}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    new-array v0, v0, [Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    return-object v0

    :cond_1
    const-string v0, "ruleRepo"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final getAutoConfigTemplateSelectionId()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    return-object v0
.end method

.method public final getConfigTemplateById(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;
    .locals 4

    const/4 v0, 0x0

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOOOO()Ljava/io/File;

    move-result-object v2

    invoke-direct {v1, v2, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    move-result p1

    if-nez p1, :cond_1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    const-string v1, "getConfigTemplateById, Template file not exists..."

    invoke-static {v1, p1}, Llyiahf/vczjk/ix8;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0

    :cond_1
    :try_start_0
    iget-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->readString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    const-class v3, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->validate()Z

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_2

    return-object p1

    :catchall_0
    move-exception p1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v1

    invoke-static {p1}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Error parse config template file: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", error message: "

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    :cond_2
    :goto_0
    return-object v0
.end method

.method public final getCustomSuCommand()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOoo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget-object v0, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/mi;->OooOoO0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getDanmuUISettings()Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    return-object v0
.end method

.method public final getEnabledRules()[Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 4

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/pb7;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lnow/fortuitous/profile/RuleInfoExt;

    invoke-virtual {v3}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getEnabled()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v1, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lnow/fortuitous/profile/RuleInfoExt;

    invoke-virtual {v2}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    const/4 v1, 0x0

    new-array v1, v1, [Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    return-object v0

    :cond_3
    const-string v0, "ruleRepo"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final getGlobalRuleVarByName(Ljava/lang/String;)[Ljava/lang/String;
    .locals 4

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    const/4 v1, 0x0

    const-string v2, "globalRuleVarRepo"

    if-eqz v0, :cond_2

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    const/4 v3, 0x0

    if-eqz v0, :cond_1

    :try_start_0
    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    new-instance v1, Lnow/fortuitous/profile/ProfileService$getGlobalRuleVarByName$currentList$1;

    invoke-direct {v1}, Lnow/fortuitous/profile/ProfileService$getGlobalRuleVarByName$currentList$1;-><init>()V

    invoke-virtual {v1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/nk3;->OooO0Oo(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object p1

    const-string v0, "fromJson(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/util/List;

    invoke-static {p1}, Lutil/CollectionUtils;->isNullOrEmpty(Ljava/util/Collection;)Z

    move-result v0

    if-nez v0, :cond_1

    new-array v0, v3, [Ljava/lang/String;

    invoke-interface {p1, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    return-object p1

    :catchall_0
    move-exception p1

    goto :goto_0

    :cond_0
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    const-string v0, "getAllGlobalRuleVarByName"

    new-array v1, v3, [Ljava/lang/Object;

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    :cond_1
    new-array p1, v3, [Ljava/lang/String;

    return-object p1

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final getLogFD()Landroid/os/ParcelFileDescriptor;
    .locals 2

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/l87;->OooO00o()Ljava/io/File;

    move-result-object v0

    const/high16 v1, 0x10000000

    invoke-static {v0, v1}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-nez v1, :cond_0

    goto :goto_1

    :cond_0
    const-string v0, "getLogFD error"

    invoke-static {v0, v1}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    const/4 v0, 0x0

    :goto_1
    check-cast v0, Landroid/os/ParcelFileDescriptor;

    return-object v0
.end method

.method public final getLogPath()Ljava/lang/String;
    .locals 3

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/l87;->OooO00o()Ljava/io/File;

    move-result-object v0

    invoke-virtual {v0}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_0
    invoke-static {}, Llyiahf/vczjk/l87;->OooO00o()Ljava/io/File;

    move-result-object v1

    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v1

    instance-of v2, v0, Llyiahf/vczjk/ts7;

    if-eqz v2, :cond_0

    move-object v0, v1

    :cond_0
    const-string v1, "getOrDefault(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/String;

    return-object v0
.end method

.method public final getRuleById(I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoOO(I)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final getRuleByName(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 2

    const-string v0, "ruleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoo0(Ljava/lang/String;)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final isAutoApplyForNewInstalledAppsEnabled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0O:Z

    return v0
.end method

.method public final isAutoConfigTemplateNotificationEnabled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO:Z

    return v0
.end method

.method public final isGlobalRuleVarByNameExists(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_0
    const-string p1, "globalRuleVarRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final isLogEnabled()Z
    .locals 1

    sget-boolean v0, Llyiahf/vczjk/l87;->OooO00o:Z

    sget-boolean v0, Llyiahf/vczjk/l87;->OooO00o:Z

    return v0
.end method

.method public final isProfileEnabled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0o:Z

    return v0
.end method

.method public final isProfileEnginePushEnabled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOo:Z

    return v0
.end method

.method public final isProfileEngineUiAutomationEnabled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOO:Z

    return v0
.end method

.method public final isRuleEnabled(I)Z
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoOO(I)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Lnow/fortuitous/profile/RuleInfoExt;->getRuleInfo()Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getEnabled()Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final isRuleExists(I)Z
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pb7;->OooOoOO(I)Lnow/fortuitous/profile/RuleInfoExt;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final isShellSuSupportInstalled()Z
    .locals 1

    iget-boolean v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoo:Z

    return v0
.end method

.method public final parseRuleOrNull(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 3

    const-string v0, "ruleString"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    const/4 v1, 0x0

    if-eqz v0, :cond_4

    iget-object v0, v0, Llyiahf/vczjk/pb7;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a27;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz p2, :cond_1

    const/4 v2, 0x1

    if-eq p2, v2, :cond_0

    move-object v0, v1

    goto :goto_1

    :cond_0
    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r95;

    new-instance v2, Ljava/io/StringReader;

    invoke-direct {v2, p1}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/r95;->OooO00o(Ljava/io/StringReader;)Lorg/jeasy/rules/core/BasicRule;

    move-result-object v0

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_0

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r95;

    new-instance v2, Ljava/io/StringReader;

    invoke-direct {v2, p1}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/r95;->OooO00o(Ljava/io/StringReader;)Lorg/jeasy/rules/core/BasicRule;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_1
    instance-of v2, v0, Llyiahf/vczjk/ts7;

    if-eqz v2, :cond_2

    move-object v0, v1

    :cond_2
    check-cast v0, Llyiahf/vczjk/nw7;

    if-eqz v0, :cond_3

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tp6;->Oooo0oO(Llyiahf/vczjk/nw7;Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v1

    :cond_3
    return-object v1

    :cond_4
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method

.method public final publishStringFact(ILjava/lang/String;J[Ljava/lang/String;)V
    .locals 1

    const-string v0, "args"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual/range {p0 .. p5}, Lnow/fortuitous/profile/ProfileService;->publishStringFactInternal(ILjava/lang/String;J[Ljava/lang/Object;)V

    return-void
.end method

.method public final publishStringFactInternal(ILjava/lang/String;J[Ljava/lang/Object;)V
    .locals 1
    .annotation build Lgithub/tornaco/android/thanos/core/annotation/DoNotStrip;
    .end annotation

    const-string v0, "args"

    invoke-static {p5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/se6;

    invoke-direct {v0, p1, p2, p5, p0}, Llyiahf/vczjk/se6;-><init>(ILjava/lang/String;[Ljava/lang/Object;Lnow/fortuitous/profile/ProfileService;)V

    invoke-virtual {p0, v0, p3, p4}, Llyiahf/vczjk/td9;->OooO0oO(Ljava/lang/Runnable;J)V

    return-void
.end method

.method public final registerRuleChangeListener(Lgithub/tornaco/android/thanos/core/profile/IRuleChangeListener;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00O:Landroid/os/RemoteCallbackList;

    invoke-virtual {v0, p1}, Landroid/os/RemoteCallbackList;->register(Landroid/os/IInterface;)Z

    return-void
.end method

.method public final removeAlarmEngine(Lgithub/tornaco/android/thanos/core/alarm/Alarm;)V
    .locals 5

    const-string v0, "alarm"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    const-string v1, "alarmEngineRepo"

    const/4 v2, 0x0

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->getAll()Ljava/util/Set;

    move-result-object v0

    const-string v3, "getAll(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v4

    invoke-static {v4, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_0

    :cond_1
    move-object v3, v2

    :goto_0
    check-cast v3, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    if-nez v3, :cond_2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "removeAlarmEngine, alarm not found: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-void

    :cond_2
    iget-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz p1, :cond_3

    invoke-virtual {p1, v3}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->remove(Ljava/lang/Object;)Z

    return-void

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2

    :cond_4
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2
.end method

.method public final removeConsoleLogSink(Lgithub/tornaco/android/thanos/core/profile/ILogSink;)V
    .locals 1

    const-string v0, "sink"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00o:Landroid/os/RemoteCallbackList;

    invoke-virtual {v0, p1}, Landroid/os/RemoteCallbackList;->unregister(Landroid/os/IInterface;)Z

    return-void
.end method

.method public final removeGlobalRuleVar(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOOoo:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    const-string p1, "globalRuleVarRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final setAlarmEnabled(Lgithub/tornaco/android/thanos/core/alarm/Alarm;Z)V
    .locals 11

    const-string v0, "alarm"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->toString()Ljava/lang/String;

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    const-string v1, "alarmEngineRepo"

    const/4 v2, 0x0

    if-eqz v0, :cond_7

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->getAll()Ljava/util/Set;

    move-result-object v0

    const-string v3, "getAll(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v4

    invoke-static {v4, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_0

    :cond_1
    move-object v3, v2

    :goto_0
    move-object v4, v3

    check-cast v4, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    if-nez v4, :cond_2

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "setAlarmEnabled, alarm not found: "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-void

    :cond_2
    const/4 v5, 0x0

    const-wide/16 v7, 0x0

    const/4 v9, 0x5

    const/4 v10, 0x0

    move v6, p2

    invoke-static/range {v4 .. v10}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->copy$default(Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;Lgithub/tornaco/android/thanos/core/alarm/Alarm;ZJILjava/lang/Object;)Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    move-result-object p2

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz v0, :cond_6

    invoke-virtual {v0, v4}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->remove(Ljava/lang/Object;)Z

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO:Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;

    if-eqz v0, :cond_5

    invoke-virtual {v0, p2}, Lgithub/tornaco/android/thanos/core/persist/JsonObjectSetRepo;->add(Ljava/lang/Object;)Z

    if-eqz v6, :cond_3

    new-instance p2, Llyiahf/vczjk/tm4;

    const/16 v0, 0xd

    invoke-direct {p2, v0, p0, p1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void

    :cond_3
    iget-object p2, p0, Lnow/fortuitous/profile/ProfileService;->OooOoO0:Llyiahf/vczjk/ld9;

    if-eqz p2, :cond_4

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ld9;->Oooo0(Lgithub/tornaco/android/thanos/core/alarm/Alarm;)V

    return-void

    :cond_4
    const-string p1, "alarmEngine"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2

    :cond_5
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2

    :cond_6
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2

    :cond_7
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v2
.end method

.method public final setAutoApplyForNewInstalledAppsEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0O:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setAutoConfigTemplateNotificationEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->oo000o:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setAutoConfigTemplateSelection(Ljava/lang/String;)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, Lnow/fortuitous/profile/ProfileService;->getConfigTemplateById(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    move-result-object v0

    if-nez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "setAutoConfigTemplateSelection, template with id:"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " not exists."

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-void

    :cond_0
    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOO0:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOoO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putString(Ljava/lang/String;Ljava/lang/String;)Z

    return-void
.end method

.method public final setCustomSuCommand(Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooOoo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    if-nez p1, :cond_0

    const-string p1, ""

    :cond_0
    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putString(Ljava/lang/String;Ljava/lang/String;)Z

    return-void
.end method

.method public final setDanmuUISettings(Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;)V
    .locals 3

    const-string v0, "settings"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    iput-object p1, p0, Lnow/fortuitous/profile/ProfileService;->Oooo0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->Ooooo00:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OooOooO:Llyiahf/vczjk/nk3;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putString(Ljava/lang/String;Ljava/lang/String;)Z

    return-void
.end method

.method public final setLogEnabled(Z)V
    .locals 2

    sput-boolean p1, Llyiahf/vczjk/l87;->OooO00o:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OooooO0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setProfileEnabled(Z)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOO0o:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->Ooooo0o:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setProfileEnginePushEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->Oooooo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setProfileEngineUiAutomationEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OooooOo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setShellSuSupportInstalled(Z)V
    .locals 3

    iput-boolean p1, p0, Lnow/fortuitous/profile/ProfileService;->OooOoo:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OooooOO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    invoke-static {}, Landroid/os/Binder;->clearCallingIdentity()J

    move-result-wide v0

    if-eqz p1, :cond_1

    new-instance p1, Llyiahf/vczjk/s87;

    const/4 v2, 0x3

    invoke-direct {p1, p0, v2}, Llyiahf/vczjk/s87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    iget-object v2, p0, Lnow/fortuitous/profile/ProfileService;->OooOo:Landroid/os/Handler;

    if-eqz v2, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/eo9;->OooO00o(Landroid/os/Handler;)Llyiahf/vczjk/cm3;

    move-result-object v2

    invoke-virtual {p0, p1, v2}, Llyiahf/vczjk/td9;->OooO0oo(Ljava/lang/Runnable;Llyiahf/vczjk/i88;)V

    goto :goto_0

    :cond_0
    const-string p1, "serverHandler"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    :goto_0
    invoke-static {v0, v1}, Landroid/os/Binder;->restoreCallingIdentity(J)V

    return-void
.end method

.method public final unRegisterRuleChangeListener(Lgithub/tornaco/android/thanos/core/profile/IRuleChangeListener;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    iget-object v0, p0, Lnow/fortuitous/profile/ProfileService;->Oooo00O:Landroid/os/RemoteCallbackList;

    invoke-virtual {v0, p1}, Landroid/os/RemoteCallbackList;->unregister(Landroid/os/IInterface;)Z

    return-void
.end method

.method public final updateRule(ILjava/lang/String;Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V
    .locals 20

    move-object/from16 v0, p0

    move/from16 v1, p1

    move-object/from16 v3, p2

    move-object/from16 v2, p3

    const/16 v4, 0x10

    const/4 v6, 0x1

    const-string v7, "|"

    invoke-virtual {v0}, Llyiahf/vczjk/aq9;->OooOOo0()V

    const-string v8, "RuleInfo content is null"

    invoke-static {v3, v8}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/td9;->OooOOO0()Landroid/content/Context;

    move-result-object v8

    :try_start_0
    invoke-static {v8}, Llyiahf/vczjk/fu6;->OooOoO(Landroid/content/Context;)[Landroid/content/pm/Signature;

    move-result-object v8

    array-length v10, v8

    move v12, v6

    const/4 v11, 0x0

    const/4 v13, 0x0

    :goto_0
    if-ge v11, v10, :cond_2

    aget-object v14, v8, v11

    add-int/lit8 v15, v13, 0x1

    const-string v16, "SHA1"

    invoke-static/range {v16 .. v16}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v9

    invoke-virtual {v14}, Landroid/content/pm/Signature;->toByteArray()[B

    move-result-object v14

    invoke-virtual {v9, v14}, Ljava/security/MessageDigest;->update([B)V

    invoke-virtual {v9}, Ljava/security/MessageDigest;->digest()[B

    move-result-object v9

    new-array v14, v4, [C

    fill-array-data v14, :array_0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/16 v16, 0x2

    :try_start_1
    array-length v5, v9

    mul-int/lit8 v5, v5, 0x2

    new-array v5, v5, [C

    array-length v4, v9

    move/from16 v17, v6

    const/4 v6, 0x0

    :goto_1
    if-ge v6, v4, :cond_0

    aget-byte v3, v9, v6

    move/from16 v18, v4

    and-int/lit16 v4, v3, 0xff

    mul-int/lit8 v19, v6, 0x2

    ushr-int/lit8 v4, v4, 0x4

    aget-char v4, v14, v4

    aput-char v4, v5, v19

    add-int/lit8 v19, v19, 0x1

    and-int/lit8 v3, v3, 0xf

    aget-char v3, v14, v3

    aput-char v3, v5, v19

    add-int/lit8 v6, v6, 0x1

    move-object/from16 v3, p2

    move/from16 v4, v18

    goto :goto_1

    :cond_0
    new-instance v3, Ljava/lang/String;

    invoke-direct {v3, v5}, Ljava/lang/String;-><init>([C)V

    const/4 v4, 0x3

    new-array v4, v4, [B

    fill-array-data v4, :array_1

    new-instance v5, Ljava/lang/String;

    sget-object v6, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-direct {v5, v4, v6}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    invoke-static {v5}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    move-result-object v4

    new-instance v5, Ljava/math/BigInteger;

    invoke-virtual {v3, v6}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    move-result-object v3

    const-string v6, "getBytes(...)"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4, v3}, Ljava/security/MessageDigest;->digest([B)[B

    move-result-object v3

    move/from16 v4, v17

    invoke-direct {v5, v4, v3}, Ljava/math/BigInteger;-><init>(I[B)V

    const/16 v3, 0x10

    invoke-virtual {v5, v3}, Ljava/math/BigInteger;->toString(I)Ljava/lang/String;

    move-result-object v4

    const-string v5, "toString(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v5, 0x20

    invoke-static {v5, v4}, Llyiahf/vczjk/z69;->OoooOo0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const-string v5, "25cc0926b09a6e73798de05977c420f7"

    filled-new-array {v7}, [Ljava/lang/String;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v5

    invoke-interface {v5, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_1

    const-string v5, "fbb0fffe49334e78f6f901c2a144314f"

    filled-new-array {v7}, [Ljava/lang/String;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v5

    invoke-interface {v5, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_1

    const-string v5, "16d5c7e8d44ba3546f725b156a925cdb"

    filled-new-array {v7}, [Ljava/lang/String;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v5

    invoke-interface {v5, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-nez v4, :cond_1

    const/4 v12, 0x0

    :cond_1
    const/16 v17, 0x1

    add-int/lit8 v11, v11, 0x1

    move v4, v3

    move v13, v15

    const/4 v6, 0x1

    move-object/from16 v3, p2

    goto/16 :goto_0

    :catchall_0
    const/16 v16, 0x2

    goto :goto_2

    :cond_2
    const/16 v16, 0x2

    move v9, v12

    goto :goto_3

    :catchall_1
    :goto_2
    const/4 v9, 0x0

    :goto_3
    if-eqz v9, :cond_5

    iget-object v4, v0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    if-eqz v4, :cond_4

    new-instance v5, Llyiahf/vczjk/iv6;

    const/4 v3, 0x1

    invoke-direct {v5, v2, v0, v1, v3}, Llyiahf/vczjk/iv6;-><init>(Landroid/os/IInterface;Ljava/lang/Object;II)V

    new-instance v7, Llyiahf/vczjk/o87;

    move/from16 v3, v16

    invoke-direct {v7, v2, v3}, Llyiahf/vczjk/o87;-><init>(Lgithub/tornaco/android/thanos/core/profile/IRuleAddCallback;I)V

    invoke-virtual {v4}, Llyiahf/vczjk/pb7;->OooOOOO()Lgithub/tornaco/android/thanos/db/profile/RuleDb;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/db/profile/RuleDb;->ruleDao()Lgithub/tornaco/android/thanos/db/profile/RuleDao;

    move-result-object v2

    invoke-interface {v2, v1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao;->loadById(I)Lgithub/tornaco/android/thanos/db/profile/RuleRecord;

    move-result-object v2

    if-nez v2, :cond_3

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Rule not found: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v7, v1}, Llyiahf/vczjk/o87;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_4

    :cond_3
    new-instance v1, Llyiahf/vczjk/m60;

    const/16 v6, 0xa

    move-object/from16 v3, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    iget-object v2, v4, Llyiahf/vczjk/pb7;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/a27;

    move/from16 v4, p4

    invoke-virtual {v2, v4, v3, v7, v1}, Llyiahf/vczjk/a27;->OooOOO(ILjava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    goto :goto_4

    :cond_4
    const-string v1, "ruleRepo"

    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v1, 0x0

    throw v1

    :cond_5
    :goto_4
    return-void

    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x41s
        0x42s
        0x43s
        0x44s
        0x45s
        0x46s
    .end array-data

    :array_1
    .array-data 1
        0x4dt
        0x44t
        0x35t
    .end array-data
.end method
