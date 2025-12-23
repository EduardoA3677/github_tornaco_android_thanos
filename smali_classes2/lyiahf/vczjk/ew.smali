.class public final Llyiahf/vczjk/ew;
.super Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/fw;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fw;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ew;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onPrefChanged(Ljava/lang/String;)V
    .locals 1

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/wg8;->OoooooO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p1}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const-string p1, "Pref changed, reload."

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ew;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {p1}, Llyiahf/vczjk/fw;->OooOo0()V

    :cond_0
    return-void
.end method
