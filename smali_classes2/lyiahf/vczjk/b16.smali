.class public final Llyiahf/vczjk/b16;
.super Llyiahf/vczjk/i88;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/kz7;


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/kz7;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const-string v0, "rx2.newthread-priority"

    const/4 v1, 0x5

    invoke-static {v0, v1}, Ljava/lang/Integer;->getInteger(Ljava/lang/String;I)Ljava/lang/Integer;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    const/16 v1, 0xa

    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    const/4 v1, 0x1

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    new-instance v1, Llyiahf/vczjk/kz7;

    const/4 v2, 0x0

    const-string v3, "RxNewThreadScheduler"

    invoke-direct {v1, v3, v0, v2}, Llyiahf/vczjk/kz7;-><init>(Ljava/lang/String;IZ)V

    sput-object v1, Llyiahf/vczjk/b16;->OooO0OO:Llyiahf/vczjk/kz7;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/b16;->OooO0OO:Llyiahf/vczjk/kz7;

    iput-object v0, p0, Llyiahf/vczjk/b16;->OooO0O0:Llyiahf/vczjk/kz7;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/h88;
    .locals 2

    new-instance v0, Llyiahf/vczjk/c16;

    iget-object v1, p0, Llyiahf/vczjk/b16;->OooO0O0:Llyiahf/vczjk/kz7;

    invoke-direct {v0, v1}, Llyiahf/vczjk/c16;-><init>(Llyiahf/vczjk/kz7;)V

    return-object v0
.end method
