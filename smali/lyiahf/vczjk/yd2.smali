.class public abstract Llyiahf/vczjk/yd2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const/4 v0, 0x0

    int-to-float v0, v0

    const/16 v1, 0x1e0

    int-to-float v1, v1

    const/16 v2, 0x384

    int-to-float v2, v2

    new-instance v3, Llyiahf/vczjk/wd2;

    invoke-direct {v3, v0}, Llyiahf/vczjk/wd2;-><init>(F)V

    new-instance v0, Llyiahf/vczjk/wd2;

    invoke-direct {v0, v1}, Llyiahf/vczjk/wd2;-><init>(F)V

    new-instance v1, Llyiahf/vczjk/wd2;

    invoke-direct {v1, v2}, Llyiahf/vczjk/wd2;-><init>(F)V

    filled-new-array {v3, v0, v1}, [Llyiahf/vczjk/wd2;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/yd2;->OooO00o:Ljava/util/Set;

    return-void
.end method
