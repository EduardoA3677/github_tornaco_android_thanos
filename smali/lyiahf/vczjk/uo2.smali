.class public abstract Llyiahf/vczjk/uo2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/n1a;

.field public static final OooO0O0:Llyiahf/vczjk/wz8;

.field public static final OooO0OO:Llyiahf/vczjk/wz8;

.field public static final OooO0Oo:Llyiahf/vczjk/wz8;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    sget-object v0, Llyiahf/vczjk/ke0;->Oooo0o:Llyiahf/vczjk/ke0;

    sget-object v1, Llyiahf/vczjk/ke0;->Oooo0oO:Llyiahf/vczjk/ke0;

    sget-object v2, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance v2, Llyiahf/vczjk/n1a;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/n1a;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    sput-object v2, Llyiahf/vczjk/uo2;->OooO00o:Llyiahf/vczjk/n1a;

    const/4 v0, 0x0

    const/4 v1, 0x0

    const/high16 v2, 0x43c80000    # 400.0f

    const/4 v3, 0x5

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uo2;->OooO0O0:Llyiahf/vczjk/wz8;

    const/4 v0, 0x1

    int-to-long v3, v0

    const/16 v5, 0x20

    shl-long v5, v3, v5

    const-wide v7, 0xffffffffL

    and-long/2addr v3, v7

    or-long/2addr v3, v5

    new-instance v5, Llyiahf/vczjk/u14;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/u14;-><init>(J)V

    invoke-static {v1, v2, v5, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v5

    sput-object v5, Llyiahf/vczjk/uo2;->OooO0OO:Llyiahf/vczjk/wz8;

    new-instance v5, Llyiahf/vczjk/b24;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-static {v1, v2, v5, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uo2;->OooO0Oo:Llyiahf/vczjk/wz8;

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/dt2;
    .locals 9

    const/4 v0, 0x1

    int-to-long v1, v0

    const/16 v3, 0x20

    shl-long v3, v1, v3

    const-wide v5, 0xffffffffL

    and-long/2addr v1, v5

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/u14;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/u14;-><init>(J)V

    const/4 v1, 0x0

    const/high16 v2, 0x43c80000    # 400.0f

    invoke-static {v1, v2, v3, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/to2;

    invoke-direct {v1, p0}, Llyiahf/vczjk/to2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance p0, Llyiahf/vczjk/dt2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, v1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {p0, v2}, Llyiahf/vczjk/dt2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object p0
.end method

.method public static OooO00o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/fp2;
    .locals 6

    and-int/lit8 v0, p2, 0x1

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    int-to-long v0, p0

    const/16 v2, 0x20

    shl-long v2, v0, v2

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    const/4 v0, 0x0

    const/high16 v1, 0x43c80000    # 400.0f

    invoke-static {v0, v1, v2, p0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p0

    :cond_0
    and-int/lit8 p2, p2, 0x2

    sget-object v0, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    if-eqz p2, :cond_1

    move-object p1, v0

    :cond_1
    sget-object p2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_2

    sget-object p1, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    goto :goto_0

    :cond_2
    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    :goto_0
    new-instance p2, Llyiahf/vczjk/lo2;

    invoke-direct {p2}, Llyiahf/vczjk/lo2;-><init>()V

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/uo2;->OooO0O0(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/fp2;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0O0(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/fp2;
    .locals 8

    new-instance v0, Llyiahf/vczjk/fp2;

    new-instance v1, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/ls0;

    invoke-direct {v4, p0, p1, p2}, Llyiahf/vczjk/ls0;-><init>(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)V

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/16 v7, 0x3b

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object v0
.end method

.method public static OooO0OO(Llyiahf/vczjk/p13;I)Llyiahf/vczjk/fp2;
    .locals 7

    and-int/lit8 p1, p1, 0x1

    if-eqz p1, :cond_0

    const/4 p0, 0x5

    const/4 p1, 0x0

    const/4 v0, 0x0

    const/high16 v1, 0x43c80000    # 400.0f

    invoke-static {v0, v1, p1, p0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p0

    :cond_0
    new-instance p1, Llyiahf/vczjk/fp2;

    new-instance v0, Llyiahf/vczjk/fz9;

    new-instance v1, Llyiahf/vczjk/iv2;

    invoke-direct {v1, p0}, Llyiahf/vczjk/iv2;-><init>(Llyiahf/vczjk/p13;)V

    const/4 v4, 0x0

    const/16 v6, 0x3e

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {p1, v0}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object p1
.end method

.method public static OooO0Oo(Llyiahf/vczjk/p13;I)Llyiahf/vczjk/dt2;
    .locals 7

    and-int/lit8 p1, p1, 0x1

    if-eqz p1, :cond_0

    const/4 p0, 0x5

    const/4 p1, 0x0

    const/4 v0, 0x0

    const/high16 v1, 0x43c80000    # 400.0f

    invoke-static {v0, v1, p1, p0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p0

    :cond_0
    new-instance p1, Llyiahf/vczjk/dt2;

    new-instance v0, Llyiahf/vczjk/fz9;

    new-instance v1, Llyiahf/vczjk/iv2;

    invoke-direct {v1, p0}, Llyiahf/vczjk/iv2;-><init>(Llyiahf/vczjk/p13;)V

    const/4 v4, 0x0

    const/16 v6, 0x3e

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {p1, v0}, Llyiahf/vczjk/dt2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object p1
.end method

.method public static OooO0o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/dt2;
    .locals 6

    and-int/lit8 v0, p2, 0x1

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    int-to-long v0, p0

    const/16 v2, 0x20

    shl-long v2, v0, v2

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    const/4 v0, 0x0

    const/high16 v1, 0x43c80000    # 400.0f

    invoke-static {v0, v1, v2, p0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object p0

    :cond_0
    and-int/lit8 p2, p2, 0x2

    sget-object v0, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    if-eqz p2, :cond_1

    move-object p1, v0

    :cond_1
    sget-object p2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_2

    sget-object p1, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    goto :goto_0

    :cond_2
    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    :goto_0
    new-instance p2, Llyiahf/vczjk/oo2;

    invoke-direct {p2}, Llyiahf/vczjk/oo2;-><init>()V

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/uo2;->OooO0oO(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/dt2;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0o0(Llyiahf/vczjk/h1a;)Llyiahf/vczjk/fp2;
    .locals 10

    sget-wide v0, Llyiahf/vczjk/ey9;->OooO0O0:J

    new-instance v2, Llyiahf/vczjk/fp2;

    new-instance v3, Llyiahf/vczjk/fz9;

    new-instance v7, Llyiahf/vczjk/s78;

    invoke-direct {v7, v0, v1, p0}, Llyiahf/vczjk/s78;-><init>(JLlyiahf/vczjk/h1a;)V

    const/4 v6, 0x0

    const/16 v9, 0x37

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v2, v3}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object v2
.end method

.method public static final OooO0oO(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/dt2;
    .locals 8

    new-instance v0, Llyiahf/vczjk/dt2;

    new-instance v1, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/ls0;

    invoke-direct {v4, p0, p1, p2}, Llyiahf/vczjk/ls0;-><init>(Llyiahf/vczjk/o4;Llyiahf/vczjk/p13;Llyiahf/vczjk/oe3;)V

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/16 v7, 0x3b

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/dt2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object v0
.end method

.method public static OooO0oo(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/fp2;
    .locals 9

    const/4 v0, 0x1

    int-to-long v1, v0

    const/16 v3, 0x20

    shl-long v3, v1, v3

    const-wide v5, 0xffffffffL

    and-long/2addr v1, v5

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/u14;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/u14;-><init>(J)V

    const/4 v1, 0x0

    const/high16 v2, 0x43c80000    # 400.0f

    invoke-static {v1, v2, v3, v0}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ro2;

    invoke-direct {v1, p0}, Llyiahf/vczjk/ro2;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance p0, Llyiahf/vczjk/fp2;

    new-instance v2, Llyiahf/vczjk/fz9;

    new-instance v4, Llyiahf/vczjk/hr8;

    invoke-direct {v4, v1, v0}, Llyiahf/vczjk/hr8;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/p13;)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3d

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/fz9;-><init>(Llyiahf/vczjk/iv2;Llyiahf/vczjk/hr8;Llyiahf/vczjk/ls0;Llyiahf/vczjk/s78;Ljava/util/LinkedHashMap;I)V

    invoke-direct {p0, v2}, Llyiahf/vczjk/fp2;-><init>(Llyiahf/vczjk/fz9;)V

    return-object p0
.end method
