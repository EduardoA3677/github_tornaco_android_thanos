.class public Llyiahf/vczjk/rp3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uca;
.implements Llyiahf/vczjk/gw8;
.implements Llyiahf/vczjk/rw;
.implements Llyiahf/vczjk/uw;
.implements Llyiahf/vczjk/a80;
.implements Llyiahf/vczjk/nr1;
.implements Llyiahf/vczjk/o16;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/rp3;

.field public static final OooOOOO:Llyiahf/vczjk/rp3;

.field public static final OooOOOo:Llyiahf/vczjk/rp3;

.field public static OooOOo:Llyiahf/vczjk/era;

.field public static final OooOOo0:Llyiahf/vczjk/rp3;

.field public static final OooOOoo:Llyiahf/vczjk/rp3;

.field public static final OooOo0:Llyiahf/vczjk/rp3;

.field public static final OooOo00:Llyiahf/vczjk/rp3;

.field public static final OooOo0O:Llyiahf/vczjk/rp3;

.field public static final OooOo0o:Llyiahf/vczjk/bpa;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOOO:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOOOO:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOOOo:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOOo0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOOoo:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOo00:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOo0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/bpa;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/rp3;->OooOo0o:Llyiahf/vczjk/bpa;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/rp3;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/rp3;Ljava/lang/String;)Llyiahf/vczjk/tw0;
    .locals 1

    new-instance p0, Llyiahf/vczjk/tw0;

    invoke-direct {p0, p1}, Llyiahf/vczjk/tw0;-><init>(Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/tw0;->OooO0Oo:Ljava/util/LinkedHashMap;

    invoke-interface {v0, p1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p0
.end method

.method public static OooOOo(Llyiahf/vczjk/iaa;Z)Llyiahf/vczjk/a52;
    .locals 6

    const-string v0, "type"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/a52;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/a52;

    return-object p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/t4a;

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-nez v0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/m06;

    if-nez v0, :cond_1

    move v3, v1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v3, v0, Llyiahf/vczjk/u4a;

    if-eqz v3, :cond_2

    check-cast v0, Llyiahf/vczjk/u4a;

    goto :goto_0

    :cond_2
    move-object v0, v2

    :goto_0
    const/4 v3, 0x1

    if-eqz v0, :cond_3

    iget-boolean v0, v0, Llyiahf/vczjk/u4a;->OooOoOO:Z

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    if-eqz p1, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/t4a;

    if-eqz v0, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v3

    goto :goto_1

    :cond_4
    sget-object v0, Llyiahf/vczjk/uk2;->OooOo0:Llyiahf/vczjk/uk2;

    invoke-virtual {v0}, Llyiahf/vczjk/uk2;->o0000OOO()Llyiahf/vczjk/l3a;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/u34;->Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/k3a;->OooO0oo:Llyiahf/vczjk/k3a;

    invoke-static {v0, v4, v5}, Llyiahf/vczjk/ye5;->OooOo(Llyiahf/vczjk/l3a;Llyiahf/vczjk/pt7;Llyiahf/vczjk/wr6;)Z

    move-result v0

    xor-int/2addr v3, v0

    :goto_1
    if-eqz v3, :cond_6

    instance-of v0, p0, Llyiahf/vczjk/k23;

    if-eqz v0, :cond_5

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/k23;

    iget-object v2, v0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_5
    new-instance v0, Llyiahf/vczjk/a52;

    invoke-static {p0}, Llyiahf/vczjk/u34;->Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object p0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p0

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/a52;-><init>(Llyiahf/vczjk/dp8;Z)V

    return-object v0

    :cond_6
    return-object v2
.end method

.method public static OooOo00(Llyiahf/vczjk/c80;F)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/c80;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    const-string v1, "em"

    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/high16 v1, 0x3f000000    # 0.5f

    iget p0, p0, Llyiahf/vczjk/c80;->OooOOO:F

    if-eqz v0, :cond_0

    mul-float/2addr p0, p1

    :cond_0
    add-float/2addr p0, v1

    float-to-int p0, p0

    return p0
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/jl5;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public OooO00o(F)Z
    .locals 1

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "not implemented"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooO0O0()Llyiahf/vczjk/pj4;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "not implemented"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooO0OO(F)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public OooO0Oo()F
    .locals 1

    const/high16 v0, 0x3f800000    # 1.0f

    return v0
.end method

.method public OooO0o(Llyiahf/vczjk/ro4;JLlyiahf/vczjk/eo3;IZ)V
    .locals 8

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object p5, p1, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast p5, Llyiahf/vczjk/v16;

    sget-object v0, Llyiahf/vczjk/v16;->OoooOO0:Llyiahf/vczjk/ft7;

    invoke-virtual {p5, p2, p3}, Llyiahf/vczjk/v16;->o0000oo(J)J

    move-result-wide v3

    iget-object p1, p1, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/v16;

    sget-object v2, Llyiahf/vczjk/v16;->OoooOo0:Llyiahf/vczjk/rp3;

    const/4 v6, 0x1

    move-object v5, p4

    move v7, p6

    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/v16;->o0000OOo(Llyiahf/vczjk/o16;JLlyiahf/vczjk/eo3;IZ)V

    return-void
.end method

.method public OooO0o0()I
    .locals 1

    const/16 v0, 0x8

    return v0
.end method

.method public OooO0oO()F
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOO0(Llyiahf/vczjk/ro4;)Z
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object p1

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-eqz p1, :cond_0

    iget-boolean p1, p1, Llyiahf/vczjk/je8;->OooOOOo:Z

    if-ne p1, v1, :cond_0

    move v0, v1

    :cond_0
    xor-int/lit8 p1, v0, 0x1

    return p1
.end method

.method public OooOO0O(Landroid/app/Application;)Ljava/util/Comparator;
    .locals 1

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x1c

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 0

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public OooOOO(Llyiahf/vczjk/rb4;F)Ljava/lang/Object;
    .locals 12

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result p2

    const/4 v0, 0x1

    if-ne p2, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OooO0Oo()V

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v1

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v3

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v5

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OoooOoo()I

    move-result p2

    const/4 v7, 0x7

    const-wide/high16 v8, 0x3ff0000000000000L    # 1.0

    if-ne p2, v7, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->Oooo0oO()D

    move-result-wide v10

    goto :goto_1

    :cond_2
    move-wide v10, v8

    :goto_1
    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/rb4;->OooOOOO()V

    :cond_3
    cmpg-double p1, v1, v8

    if-gtz p1, :cond_4

    cmpg-double p1, v3, v8

    if-gtz p1, :cond_4

    cmpg-double p1, v5, v8

    if-gtz p1, :cond_4

    const-wide p1, 0x406fe00000000000L    # 255.0

    mul-double/2addr v1, p1

    mul-double/2addr v3, p1

    mul-double/2addr v5, p1

    cmpg-double v0, v10, v8

    if-gtz v0, :cond_4

    mul-double/2addr v10, p1

    :cond_4
    double-to-int p1, v10

    double-to-int p2, v1

    double-to-int v0, v3

    double-to-int v1, v5

    invoke-static {p1, p2, v0, v1}, Landroid/graphics/Color;->argb(IIII)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method

.method public OooOOO0(Ljava/lang/reflect/Method;I)Ljava/lang/String;
    .locals 1

    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "parameter #"

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    add-int/lit8 p2, p2, 0x1

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public declared-synchronized OooOOOO(Ljava/lang/String;)Llyiahf/vczjk/tw0;
    .locals 7

    monitor-enter p0

    :try_start_0
    const-string v0, "javaName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/tw0;->OooO0Oo:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tw0;

    if-nez v1, :cond_3

    const-string v1, "TLS_"

    const/4 v2, 0x0

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v3

    const-string v4, "SSL_"

    const-string v5, "this as java.lang.String).substring(startIndex)"

    const/4 v6, 0x4

    if-eqz v3, :cond_0

    invoke-virtual {p1, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_0
    invoke-static {p1, v4, v2}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {p1, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_1
    move-object v1, p1

    :goto_0
    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tw0;

    if-nez v1, :cond_2

    new-instance v1, Llyiahf/vczjk/tw0;

    invoke-direct {v1, p1}, Llyiahf/vczjk/tw0;-><init>(Ljava/lang/String;)V

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_1
    invoke-interface {v0, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_3
    monitor-exit p0

    return-object v1

    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public OooOOOo(Ljava/lang/reflect/Method;Ljava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/AssertionError;

    invoke-direct {p1}, Ljava/lang/AssertionError;-><init>()V

    throw p1
.end method

.method public OooOOo0(Ljava/lang/reflect/Method;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public OooOOoo(Landroid/app/Application;Llyiahf/vczjk/wu;)Ljava/lang/String;
    .locals 0

    iget-object p1, p2, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-wide p1, p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->lastUpdateTime:J

    invoke-static {p1, p2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OooOo0(Llyiahf/vczjk/zz6;II)V
    .locals 0

    return-void
.end method

.method public OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;
    .locals 1

    const-string v0, "javaElement"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hz7;

    check-cast p1, Llyiahf/vczjk/gm7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/hz7;-><init>(Llyiahf/vczjk/gm7;)V

    return-object v0
.end method

.method public Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x1b

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    return-object p1
.end method

.method public isEmpty()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "model"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p2, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-wide p1, p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->lastUpdateTime:J

    invoke-static {p1, p2}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object p1

    const-string p2, "formatLongForMessageTime(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/rp3;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    const-string v0, "StructuralEqualityPolicy"

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x8
        :pswitch_0
    .end packed-switch
.end method
