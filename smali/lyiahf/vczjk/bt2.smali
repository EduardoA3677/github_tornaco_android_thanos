.class public abstract Llyiahf/vczjk/bt2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const-string v0, "image/heic"

    const-string v1, "image/heif"

    const-string v2, "image/jpeg"

    const-string v3, "image/webp"

    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/bt2;->OooO00o:Ljava/util/Set;

    return-void
.end method
