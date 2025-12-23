.class public abstract Llyiahf/vczjk/ge8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/am;

.field public static final OooO0O0:Llyiahf/vczjk/n1a;

.field public static final OooO0OO:J

.field public static final OooO0Oo:Llyiahf/vczjk/wz8;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    new-instance v0, Llyiahf/vczjk/am;

    const/high16 v1, 0x7fc00000    # Float.NaN

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/am;-><init>(FF)V

    sput-object v0, Llyiahf/vczjk/ge8;->OooO00o:Llyiahf/vczjk/am;

    sget-object v0, Llyiahf/vczjk/o68;->OooOoO:Llyiahf/vczjk/o68;

    sget-object v1, Llyiahf/vczjk/o68;->OooOoOO:Llyiahf/vczjk/o68;

    sget-object v2, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance v2, Llyiahf/vczjk/n1a;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/n1a;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    sput-object v2, Llyiahf/vczjk/ge8;->OooO0O0:Llyiahf/vczjk/n1a;

    const v0, 0x3c23d70a    # 0.01f

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v3, v0

    const/16 v0, 0x20

    shl-long v0, v1, v0

    const-wide v5, 0xffffffffL

    and-long v2, v3, v5

    or-long/2addr v0, v2

    sput-wide v0, Llyiahf/vczjk/ge8;->OooO0OO:J

    new-instance v2, Llyiahf/vczjk/wz8;

    new-instance v3, Llyiahf/vczjk/p86;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-direct {v2, v3}, Llyiahf/vczjk/wz8;-><init>(Ljava/lang/Object;)V

    sput-object v2, Llyiahf/vczjk/ge8;->OooO0Oo:Llyiahf/vczjk/wz8;

    return-void
.end method
