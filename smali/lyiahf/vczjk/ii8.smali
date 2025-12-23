.class public final Llyiahf/vczjk/ii8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/og8;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/ii8;

.field public static final OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ii8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ii8;->OooO00o:Llyiahf/vczjk/ii8;

    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;->newBuilder()Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->setIsScreenOffFreezeEnabled(Z)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object v0

    invoke-virtual {v0, v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->setIsTaskRemoveFreezeEnabled(Z)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->setIsDisableDOL(Z)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object v0

    invoke-virtual {v0}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->build()Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    move-result-object v0

    const-string v1, "build(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/ii8;->OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/io/InputStream;)Ljava/lang/Object;
    .locals 2

    :try_start_0
    invoke-static {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;->parseFrom(Ljava/io/InputStream;)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    move-result-object p1

    const-string v0, "parseFrom(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catch Lcom/google/protobuf/InvalidProtocolBufferException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/is1;

    const-string v1, "Cannot read proto."

    invoke-direct {v0, v1, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final OooO0O0(Ljava/lang/Object;Ljava/io/OutputStream;)V
    .locals 0

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    invoke-virtual {p1, p2}, Lcom/google/protobuf/AbstractMessageLite;->writeTo(Ljava/io/OutputStream;)V

    return-void
.end method

.method public final getDefaultValue()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ii8;->OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    return-object v0
.end method
