.class public final Llyiahf/vczjk/sm2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qj0;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/yn4;

.field public static final OooOOO0:Llyiahf/vczjk/sm2;

.field public static final OooOOOO:Llyiahf/vczjk/i62;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/sm2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/sm2;->OooOOO0:Llyiahf/vczjk/sm2;

    sget-object v0, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    sput-object v0, Llyiahf/vczjk/sm2;->OooOOO:Llyiahf/vczjk/yn4;

    new-instance v0, Llyiahf/vczjk/i62;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/i62;-><init>(FF)V

    sput-object v0, Llyiahf/vczjk/sm2;->OooOOOO:Llyiahf/vczjk/i62;

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/f62;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sm2;->OooOOOO:Llyiahf/vczjk/i62;

    return-object v0
.end method

.method public final OooO0o0()J
    .locals 2

    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    return-wide v0
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sm2;->OooOOO:Llyiahf/vczjk/yn4;

    return-object v0
.end method
