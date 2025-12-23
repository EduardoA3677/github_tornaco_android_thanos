.class public final Llyiahf/vczjk/ro9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static OooO0oO:Llyiahf/vczjk/ze3;


# instance fields
.field public final OooO00o:Lnow/fortuitous/thanos/ThanosApp;

.field public final OooO0O0:Ljava/util/LinkedHashMap;

.field public final OooO0OO:Llyiahf/vczjk/sc9;

.field public final OooO0Oo:Llyiahf/vczjk/sc9;

.field public final OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0o0:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/m99;

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/m99;-><init>(IB)V

    sput-object v0, Llyiahf/vczjk/ro9;->OooO0oO:Llyiahf/vczjk/ze3;

    return-void
.end method

.method public constructor <init>(Lnow/fortuitous/thanos/ThanosApp;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO00o:Lnow/fortuitous/thanos/ThanosApp;

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

    new-instance p1, Llyiahf/vczjk/io9;

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/io9;-><init>(Llyiahf/vczjk/ro9;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO0OO:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/io9;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/io9;-><init>(Llyiahf/vczjk/ro9;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO0Oo:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/io9;

    const/4 v0, 0x2

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/io9;-><init>(Llyiahf/vczjk/ro9;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO0o0:Llyiahf/vczjk/sc9;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "App"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/ro9;->OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

    return-void
.end method
