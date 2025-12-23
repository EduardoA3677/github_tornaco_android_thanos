.class public final Llyiahf/vczjk/mv6;
.super Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/uv6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uv6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mv6;->OooO0o0:Llyiahf/vczjk/uv6;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onPrefChanged(Ljava/lang/String;)V
    .locals 1

    const-string v0, "Pref changed: %s, reload."

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/zsa;->OooooO0(Ljava/lang/String;[Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mv6;->OooO0o0:Llyiahf/vczjk/uv6;

    invoke-virtual {p1}, Llyiahf/vczjk/uv6;->o000oOoO()V

    return-void
.end method
