.class public abstract synthetic Llyiahf/vczjk/oo4;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    invoke-static {}, Llyiahf/vczjk/lo4;->values()[Llyiahf/vczjk/lo4;

    move-result-object v0

    array-length v0, v0

    new-array v0, v0, [I

    :try_start_0
    sget-object v1, Llyiahf/vczjk/lo4;->OooOOO0:Llyiahf/vczjk/lo4;

    const/4 v1, 0x1

    const/4 v2, 0x4

    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    sput-object v0, Llyiahf/vczjk/oo4;->OooO00o:[I

    return-void
.end method
