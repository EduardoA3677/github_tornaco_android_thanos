.class public final Llyiahf/vczjk/n95;
.super Llyiahf/vczjk/g76;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/h76;


# instance fields
.field public OooO0O0:D

.field public OooO0OO:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/n95;

    invoke-direct {v0}, Llyiahf/vczjk/n95;-><init>()V

    const/16 v1, 0x40

    invoke-static {v1, v0}, Llyiahf/vczjk/h76;->OooO00o(ILlyiahf/vczjk/g76;)Llyiahf/vczjk/h76;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/n95;->OooO0Oo:Llyiahf/vczjk/h76;

    const/high16 v1, 0x3f000000    # 0.5f

    iput v1, v0, Llyiahf/vczjk/h76;->OooO0o:F

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/g76;-><init>()V

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/n95;->OooO0O0:D

    iput-wide v0, p0, Llyiahf/vczjk/n95;->OooO0OO:D

    return-void
.end method

.method public static OooO0O0(DD)Llyiahf/vczjk/n95;
    .locals 1

    sget-object v0, Llyiahf/vczjk/n95;->OooO0Oo:Llyiahf/vczjk/h76;

    invoke-virtual {v0}, Llyiahf/vczjk/h76;->OooO0O0()Llyiahf/vczjk/g76;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n95;

    iput-wide p0, v0, Llyiahf/vczjk/n95;->OooO0O0:D

    iput-wide p2, v0, Llyiahf/vczjk/n95;->OooO0OO:D

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/g76;
    .locals 1

    new-instance v0, Llyiahf/vczjk/n95;

    invoke-direct {v0}, Llyiahf/vczjk/n95;-><init>()V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "MPPointD, x: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v1, p0, Llyiahf/vczjk/n95;->OooO0O0:D

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    const-string v1, ", y: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v1, p0, Llyiahf/vczjk/n95;->OooO0OO:D

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
