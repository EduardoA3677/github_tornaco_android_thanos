.class public final Llyiahf/vczjk/lw6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/og8;


# static fields
.field public static final OooO00o:Llyiahf/vczjk/lw6;

.field public static final OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/lw6;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/lw6;->OooO00o:Llyiahf/vczjk/lw6;

    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;->getDefaultInstance()Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    move-result-object v0

    const-string v1, "getDefaultInstance(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/lw6;->OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/io/InputStream;)Ljava/lang/Object;
    .locals 2

    :try_start_0
    invoke-static {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;->parseFrom(Ljava/io/InputStream;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

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

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    invoke-virtual {p1, p2}, Lcom/google/protobuf/AbstractMessageLite;->writeTo(Ljava/io/OutputStream;)V

    return-void
.end method

.method public final getDefaultValue()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/lw6;->OooO0O0:Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSetList;

    return-object v0
.end method
