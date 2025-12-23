.class public abstract synthetic Llyiahf/vczjk/pd9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Runtime;->availableProcessors()I

    move-result v0

    sput v0, Llyiahf/vczjk/pd9;->OooO00o:I

    return-void
.end method
