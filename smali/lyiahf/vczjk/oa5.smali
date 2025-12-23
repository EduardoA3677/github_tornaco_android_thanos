.class public final Llyiahf/vczjk/oa5;
.super Lgithub/tornaco/android/thanos/core/IPkgChangeListener$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/ua5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ua5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oa5;->OooO0o0:Llyiahf/vczjk/ua5;

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/IPkgChangeListener$Stub;-><init>()V

    return-void
.end method


# virtual methods
.method public final onChanged(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 1

    const-string v0, "pkg"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/oa5;->OooO0o0:Llyiahf/vczjk/ua5;

    iget-object v0, p1, Llyiahf/vczjk/ua5;->OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object p1, p1, Llyiahf/vczjk/ua5;->OooO0o:Llyiahf/vczjk/e28;

    invoke-virtual {p1}, Llyiahf/vczjk/e28;->OooO0OO()V

    return-void
.end method
