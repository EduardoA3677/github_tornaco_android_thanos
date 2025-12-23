.class public final Llyiahf/vczjk/h36;
.super Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/i36;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i36;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h36;->OooO0o0:Llyiahf/vczjk/i36;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onPrefChanged(Ljava/lang/String;)V
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/wg8;->OoooO00:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p1}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/wg8;->OoooO0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p1}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    :goto_0
    const-string p1, "Pref changed, reload."

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/h36;->OooO0o0:Llyiahf/vczjk/i36;

    invoke-virtual {p1}, Llyiahf/vczjk/i36;->OooOoOO()V

    return-void
.end method
