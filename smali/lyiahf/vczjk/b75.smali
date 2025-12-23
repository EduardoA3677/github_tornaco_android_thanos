.class public abstract synthetic Llyiahf/vczjk/b75;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:[I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    invoke-static {}, Llyiahf/vczjk/x75;->values()[Llyiahf/vczjk/x75;

    move-result-object v0

    array-length v0, v0

    new-array v0, v0, [I

    :try_start_0
    sget-object v1, Llyiahf/vczjk/x75;->OooOOO0:Llyiahf/vczjk/x75;

    const/4 v1, 0x1

    aput v1, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    sput-object v0, Llyiahf/vczjk/b75;->OooO00o:[I

    return-void
.end method
