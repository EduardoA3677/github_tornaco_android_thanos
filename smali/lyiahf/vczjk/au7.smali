.class public abstract Llyiahf/vczjk/au7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;

.field public static final OooO0O0:Llyiahf/vczjk/eu7;

.field public static final OooO0OO:Llyiahf/vczjk/eu7;

.field public static final OooO0Oo:Llyiahf/vczjk/st7;

.field public static final OooO0o:Llyiahf/vczjk/st7;

.field public static final OooO0o0:Llyiahf/vczjk/st7;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    sget-object v0, Llyiahf/vczjk/o24;->OooOo0o:Llyiahf/vczjk/o24;

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/au7;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v0, Llyiahf/vczjk/eu7;

    sget-wide v1, Llyiahf/vczjk/n21;->OooOO0:J

    const/4 v3, 0x1

    const/high16 v4, 0x7fc00000    # Float.NaN

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/eu7;-><init>(ZFJ)V

    sput-object v0, Llyiahf/vczjk/au7;->OooO0O0:Llyiahf/vczjk/eu7;

    new-instance v0, Llyiahf/vczjk/eu7;

    const/4 v3, 0x0

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/eu7;-><init>(ZFJ)V

    sput-object v0, Llyiahf/vczjk/au7;->OooO0OO:Llyiahf/vczjk/eu7;

    new-instance v0, Llyiahf/vczjk/st7;

    const v1, 0x3e23d70a    # 0.16f

    const v2, 0x3e75c28f    # 0.24f

    const v3, 0x3da3d70a    # 0.08f

    invoke-direct {v0, v1, v2, v3, v2}, Llyiahf/vczjk/st7;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/au7;->OooO0Oo:Llyiahf/vczjk/st7;

    new-instance v0, Llyiahf/vczjk/st7;

    const v1, 0x3df5c28f    # 0.12f

    const v2, 0x3d23d70a    # 0.04f

    invoke-direct {v0, v3, v1, v2, v1}, Llyiahf/vczjk/st7;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/au7;->OooO0o0:Llyiahf/vczjk/st7;

    new-instance v0, Llyiahf/vczjk/st7;

    const v4, 0x3dcccccd    # 0.1f

    invoke-direct {v0, v3, v1, v2, v4}, Llyiahf/vczjk/st7;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/au7;->OooO0o:Llyiahf/vczjk/st7;

    return-void
.end method

.method public static OooO00o(IZ)Llyiahf/vczjk/eu7;
    .locals 4

    sget v0, Llyiahf/vczjk/ut3;->OooO00o:F

    and-int/lit8 v1, p0, 0x1

    if-eqz v1, :cond_0

    const/4 p1, 0x1

    :cond_0
    and-int/lit8 p0, p0, 0x2

    const/high16 v1, 0x7fc00000    # Float.NaN

    if-eqz p0, :cond_1

    move v0, v1

    :cond_1
    sget-wide v2, Llyiahf/vczjk/n21;->OooOO0:J

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p0

    if-eqz p0, :cond_3

    invoke-static {v2, v3, v2, v3}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result p0

    if-eqz p0, :cond_3

    if-eqz p1, :cond_2

    sget-object p0, Llyiahf/vczjk/au7;->OooO0O0:Llyiahf/vczjk/eu7;

    return-object p0

    :cond_2
    sget-object p0, Llyiahf/vczjk/au7;->OooO0OO:Llyiahf/vczjk/eu7;

    return-object p0

    :cond_3
    new-instance p0, Llyiahf/vczjk/eu7;

    invoke-direct {p0, p1, v0, v2, v3}, Llyiahf/vczjk/eu7;-><init>(ZFJ)V

    return-object p0
.end method
