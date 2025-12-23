.class public final Llyiahf/vczjk/kt1;
.super Llyiahf/vczjk/st1;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/kt1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/kt1;

    const-wide/16 v1, 0x0

    invoke-static {v1, v2}, Ljava/lang/Double;->doubleToLongBits(D)J

    move-result-wide v1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/st1;-><init>(J)V

    sput-object v0, Llyiahf/vczjk/kt1;->OooOOO:Llyiahf/vczjk/kt1;

    const-wide/high16 v0, 0x3ff0000000000000L    # 1.0

    invoke-static {v0, v1}, Ljava/lang/Double;->doubleToLongBits(D)J

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/st1;->OooOOO0:J

    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/String;
    .locals 1

    const-string v0, "double"

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/p1a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/p1a;->OooOo0:Llyiahf/vczjk/p1a;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    iget-wide v0, p0, Llyiahf/vczjk/st1;->OooOOO0:J

    invoke-static {v0, v1}, Llyiahf/vczjk/u34;->OoooooO(J)Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v1}, Ljava/lang/Double;->longBitsToDouble(J)D

    move-result-wide v0

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "double{0x"

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " / "

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v0, v1}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    const-string v0, "}"

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
