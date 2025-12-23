.class public final Llyiahf/vczjk/uq2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/uq2;

.field public static final OooO0O0:Llyiahf/vczjk/iq2;

.field public static final OooO0OO:Llyiahf/vczjk/eq2;

.field public static final OooO0Oo:Llyiahf/vczjk/rq2;

.field public static final OooO0o:Ljava/util/Set;

.field public static final OooO0o0:Llyiahf/vczjk/rq2;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/uq2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    sget-object v0, Llyiahf/vczjk/iq2;->OooOOO0:Llyiahf/vczjk/iq2;

    sput-object v0, Llyiahf/vczjk/uq2;->OooO0O0:Llyiahf/vczjk/iq2;

    new-instance v0, Llyiahf/vczjk/eq2;

    sget-object v1, Llyiahf/vczjk/gq2;->OooOOO0:Llyiahf/vczjk/gq2;

    invoke-virtual {v1}, Llyiahf/vczjk/gq2;->OooO00o()Ljava/lang/String;

    move-result-object v1

    const-string v2, "unknown class"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const/4 v3, 0x1

    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v2

    invoke-static {v1, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/eq2;-><init>(Llyiahf/vczjk/qt5;)V

    sput-object v0, Llyiahf/vczjk/uq2;->OooO0OO:Llyiahf/vczjk/eq2;

    sget-object v0, Llyiahf/vczjk/tq2;->OooOOo:Llyiahf/vczjk/tq2;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/String;

    invoke-static {v0, v2}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uq2;->OooO0Oo:Llyiahf/vczjk/rq2;

    sget-object v0, Llyiahf/vczjk/tq2;->OooOooo:Llyiahf/vczjk/tq2;

    new-array v1, v1, [Ljava/lang/String;

    invoke-static {v0, v1}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uq2;->OooO0o0:Llyiahf/vczjk/rq2;

    new-instance v0, Llyiahf/vczjk/jq2;

    invoke-direct {v0}, Llyiahf/vczjk/jq2;-><init>()V

    invoke-static {v0}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/uq2;->OooO0o:Ljava/util/Set;

    return-void
.end method

.method public static final varargs OooO00o(Llyiahf/vczjk/pq2;Z[Ljava/lang/String;)Llyiahf/vczjk/oq2;
    .locals 2

    const-string v0, "formatParams"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p1, :cond_0

    new-instance p1, Llyiahf/vczjk/nr9;

    array-length v1, p2

    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Ljava/lang/String;

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v0, p2

    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Ljava/lang/String;

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/oq2;-><init>(Llyiahf/vczjk/pq2;[Ljava/lang/String;)V

    return-object p1

    :cond_0
    new-instance p1, Llyiahf/vczjk/oq2;

    array-length v0, p2

    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    check-cast p2, [Ljava/lang/String;

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/oq2;-><init>(Llyiahf/vczjk/pq2;[Ljava/lang/String;)V

    return-object p1
.end method

.method public static final varargs OooO0O0(Llyiahf/vczjk/pq2;[Ljava/lang/String;)Llyiahf/vczjk/oq2;
    .locals 1

    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    const/4 v0, 0x0

    invoke-static {p0, v0, p1}, Llyiahf/vczjk/uq2;->OooO00o(Llyiahf/vczjk/pq2;Z[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object p0

    return-object p0
.end method

.method public static final varargs OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;
    .locals 3

    const-string v0, "kind"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    array-length v1, p1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    const-string v1, "formatParams"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v1, p1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Ljava/lang/String;

    invoke-static {p0, v1}, Llyiahf/vczjk/uq2;->OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;

    move-result-object v1

    array-length v2, p1

    invoke-static {p1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    invoke-static {p0, v0, v1, p1}, Llyiahf/vczjk/uq2;->OooO0o0(Llyiahf/vczjk/tq2;Ljava/util/List;Llyiahf/vczjk/n3a;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p0

    return-object p0
.end method

.method public static varargs OooO0Oo(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/sq2;
    .locals 2

    const-string v0, "kind"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "formatParams"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/sq2;

    array-length v1, p1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Ljava/lang/String;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/sq2;-><init>(Llyiahf/vczjk/tq2;[Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooO0o(Llyiahf/vczjk/v02;)Z
    .locals 1

    if-eqz p0, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/eq2;

    if-nez v0, :cond_0

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/eq2;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/uq2;->OooO0O0:Llyiahf/vczjk/iq2;

    if-ne p0, v0, :cond_1

    :cond_0
    const/4 p0, 0x1

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static varargs OooO0o0(Llyiahf/vczjk/tq2;Ljava/util/List;Llyiahf/vczjk/n3a;[Ljava/lang/String;)Llyiahf/vczjk/rq2;
    .locals 8

    const-string v0, "kind"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "formatParams"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/rq2;

    sget-object v0, Llyiahf/vczjk/pq2;->OooOOOo:Llyiahf/vczjk/pq2;

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/uq2;->OooO0O0(Llyiahf/vczjk/pq2;[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object v3

    array-length v0, p3

    invoke-static {p3, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p3

    move-object v7, p3

    check-cast v7, [Ljava/lang/String;

    const/4 v6, 0x0

    move-object v4, p0

    move-object v5, p1

    move-object v2, p2

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/rq2;-><init>(Llyiahf/vczjk/n3a;Llyiahf/vczjk/oq2;Llyiahf/vczjk/tq2;Ljava/util/List;Z[Ljava/lang/String;)V

    return-object v1
.end method
