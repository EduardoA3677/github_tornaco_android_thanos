.class public abstract Llyiahf/vczjk/xba;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Lgithub/tornaco/android/thanos/core/Logger;

.field public static OooO0O0:I

.field public static final OooO0OO:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "ShortV"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/xba;->OooO00o:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance v0, Llyiahf/vczjk/na9;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/na9;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xba;->OooO0OO:Llyiahf/vczjk/sc9;

    return-void
.end method
