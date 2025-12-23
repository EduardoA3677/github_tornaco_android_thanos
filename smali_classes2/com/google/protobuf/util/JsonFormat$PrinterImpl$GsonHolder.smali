.class Lcom/google/protobuf/util/JsonFormat$PrinterImpl$GsonHolder;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/protobuf/util/JsonFormat$PrinterImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "GsonHolder"
.end annotation


# static fields
.field private static final DEFAULT_GSON:Llyiahf/vczjk/nk3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/ok3;

    invoke-direct {v0}, Llyiahf/vczjk/ok3;-><init>()V

    invoke-virtual {v0}, Llyiahf/vczjk/ok3;->OooO00o()Llyiahf/vczjk/nk3;

    move-result-object v0

    sput-object v0, Lcom/google/protobuf/util/JsonFormat$PrinterImpl$GsonHolder;->DEFAULT_GSON:Llyiahf/vczjk/nk3;

    return-void
.end method

.method private constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static synthetic access$700()Llyiahf/vczjk/nk3;
    .locals 1

    sget-object v0, Lcom/google/protobuf/util/JsonFormat$PrinterImpl$GsonHolder;->DEFAULT_GSON:Llyiahf/vczjk/nk3;

    return-object v0
.end method
